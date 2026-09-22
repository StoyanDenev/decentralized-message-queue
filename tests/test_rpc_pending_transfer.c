/* SPDX-License-Identifier: Apache-2.0 */
#include <determ/rpc/json_rpc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef DETERM_TEST_FIXTURE_DIR
#define DETERM_TEST_FIXTURE_DIR "tests/fixtures"
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"pending RPC line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static pending_transfer_pool_t pool;
static pending_shard_t buckets[PENDING_TRANSFER_MAX_SHARDS], before[PENDING_TRANSFER_MAX_SHARDS];
static char response[RPC_MAX_RESPONSE_LEN], request[1200], hex[795];
static void fixture(const char *name) {
    char path[1024]; unsigned char frame[PENDING_TRANSFER_FRAME_SIZE];
    CHECK(snprintf(path,sizeof(path),"%s/%s",DETERM_TEST_FIXTURE_DIR,name)>0);
    FILE *f=fopen(path,"rb"); CHECK(f!=NULL);
    CHECK(fread(frame,1,sizeof(frame),f)==sizeof(frame) && fgetc(f)==EOF); CHECK(fclose(f)==0);
    for(size_t i=0;i<sizeof(frame);i++) sprintf(hex+i*2,"%02x",frame[i]);
}
static void submit_request(const char *id) {
    CHECK(snprintf(request,sizeof(request),"{\"id\":%s,\"params\":{\"frame\":\"%s\"},\"method\":\"submit_pending_transfer\",\"jsonrpc\":\"2.0\"}",id,hex)>0);
}
static void dispatch(const char *req,const rpc_context_t *ctx) {
    int n=rpc_dispatch_context(req,strlen(req),ctx,response,sizeof(response));
    CHECK(n>0 && (size_t)n==strlen(response));
}
static void fails(const char *req,const rpc_context_t *ctx) {
    memcpy(before,buckets,sizeof(before)); dispatch(req,ctx);
    CHECK(strstr(response,"\"error\"") && !strstr(response,"\"result\""));
    CHECK(memcmp(before,buckets,sizeof(before))==0);
}
int main(void) {
    shard_routing_config_t routing; uint8_t zero[32]={0};
    rpc_context_t ctx; memset(&ctx,0,sizeof(ctx));
    CHECK(shard_routing_init(&routing,1,zero)==0);
    CHECK(pending_transfer_init(&pool,buckets,PENDING_TRANSFER_MAX_SHARDS,&routing,zero)==0);
    fixture("pending_transfer_default.bin"); submit_request("\"method\"");
    fails(request,&ctx); CHECK(strstr(response,"-32001"));
    ctx.pending=&pool;
    memcpy(before,buckets,sizeof(before));
    char small[RPC_PENDING_SUBMIT_RESPONSE_LEN+2]; memset(small,0x55,sizeof(small));
    CHECK(rpc_dispatch_context(request,strlen(request),&ctx,small,64)==-1);
    CHECK(memcmp(before,buckets,sizeof(before))==0 && (unsigned char)small[64]==0x55);
    CHECK(rpc_dispatch_context(request,strlen(request),&ctx,small,RPC_PENDING_SUBMIT_RESPONSE_LEN-1)==-1);
    CHECK(memcmp(before,buckets,sizeof(before))==0 && (unsigned char)small[RPC_PENDING_SUBMIT_RESPONSE_LEN]==0x55);
    CHECK(rpc_dispatch_context(request,strlen(request),&ctx,small,RPC_PENDING_SUBMIT_RESPONSE_LEN)>0);
    CHECK(strstr(small,"\"status\":\"inserted\"") && strstr(small,"\"id\":\"method\""));
    dispatch(request,&ctx); CHECK(strstr(response,"\"status\":\"duplicate\""));
    CHECK(strstr(response,"\"state_validated\":false") && strstr(response,"\"config_source\":\"local\""));
    CHECK(strstr(response,"e8bdf98cab401b55f800594568a09084d3311c513a9e52241751a54b1f5e4d72"));
    const char *fill[]={"pending_transfer_nonce_2.bin","pending_transfer_nonce_3.bin","pending_transfer_nonce_4.bin"};
    for(size_t i=0;i<3;i++) {
        fixture(fill[i]); submit_request("1"); dispatch(request,&ctx);
        CHECK(strstr(response,"\"status\":\"inserted\""));
    }
    fixture("pending_transfer_default.bin");
    const char *list="{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":0},\"id\":4}";
    dispatch(list,&ctx); CHECK(strstr(response,hex)); CHECK(strstr(response,"\"id\":4"));
    for(size_t i=0;i<3;i++) { fixture(fill[i]); CHECK(strstr(response,hex)); }
    fixture("pending_transfer_default.bin");
    size_t exact=strlen(response); char expected[RPC_MAX_RESPONSE_LEN]; memcpy(expected,response,exact+1);
    CHECK(rpc_dispatch_context(list,strlen(list),&ctx,response,exact)==-1);
    CHECK(rpc_dispatch_context(list,strlen(list),&ctx,response,exact+1)==(int)exact);
    CHECK(strcmp(response,expected)==0);
    /* Context metadata is owned by the pool, independent of the query config. */
    CHECK(shard_routing_init(&routing,7,zero)==0); ctx.routing=&routing;
    dispatch(list,&ctx); CHECK(strstr(response,"\"shard_count\":1"));
    /* Invalid signature on a resident hash must not return duplicate. */
    hex[530]=hex[530]=='0'?'1':'0'; submit_request("9"); fails(request,&ctx);
    CHECK(strstr(response,"-32002") && strstr(response,"\"id\":9"));
    fixture("pending_transfer_default.bin"); submit_request("null");
    const char *bad[]={
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":1}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":4294967296}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":-1}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":0.0}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":00}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":\"0\"}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":0,\"shard_id\":0}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":0,\"genesis\":0}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"submit_pending_transfer\",\"params\":{\"frame\":\"aa\"}}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"submit_pending_transfer\",\"params\":[],\"id\":\"bad\"}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"submit_pending_transfer\",\"params\":{},\"id\":1,\"id\":2}",
      "{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":0}}"
    };
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) fails(bad[i],&ctx);
    fails(bad[9],&ctx); CHECK(strstr(response,"-32602") && strstr(response,"\"id\":\"bad\""));
    size_t n=strlen(request); memset(request+n,' ',RPC_PENDING_MAX_REQUEST_LEN-n); request[RPC_PENDING_MAX_REQUEST_LEN]=0;
    dispatch(request,&ctx); CHECK(strstr(response,"\"duplicate\""));
    request[RPC_PENDING_MAX_REQUEST_LEN]=' '; request[RPC_PENDING_MAX_REQUEST_LEN+1]=0; fails(request,&ctx);
    /* An authenticated non-default frame demonstrates copied chain/salt config. */
    uint8_t ramp[32]; for(size_t i=0;i<32;i++) ramp[i]=(uint8_t)i;
    CHECK(shard_routing_init(&routing,7,ramp)==0);
    CHECK(pending_transfer_init(&pool,buckets,PENDING_TRANSFER_MAX_SHARDS,&routing,ramp)==0);
    fixture("pending_transfer_routed.bin"); submit_request("\"12345678901234567890123456789012\"");
    CHECK(rpc_dispatch_context(request,strlen(request),&ctx,small,RPC_PENDING_SUBMIT_RESPONSE_LEN)>0);
    CHECK(strstr(small,"\"shard_id\":6") && strstr(small,"\"status\":\"inserted\""));
    dispatch("{\"jsonrpc\":\"2.0\",\"method\":\"get_pending_transfers\",\"params\":{\"shard_id\":6}}",&ctx);
    CHECK(strstr(response,hex));
    dispatch(list,&ctx); CHECK(strstr(response,"\"frames\":[]"));
    puts("PASS: opt-in pending RPC, signed frames, context, strict grammar and atomic output bounds");
    return 0;
}
