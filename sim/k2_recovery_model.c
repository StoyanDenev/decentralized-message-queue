/* SPDX-License-Identifier: Apache-2.0 — TEST MODEL ONLY, see header. */
#include "k2_recovery_model.h"
#include <determ/crypto/sha2/sha2.h>
#include <determ/crypto/ed25519/ed25519.h>
#include <string.h>
static void be(uint8_t *p, uint64_t x, size_t n) { while (n) { p[--n]=(uint8_t)x; x>>=8; } }
static uint64_t read_be(const uint8_t *p, size_t n) { uint64_t v=0; while(n--) v=(v<<8)|*p++; return v; }
void k2_model_tx_id(const triple_entry_tx_t *tx, uint8_t out[32]) {
    uint8_t bytes[LEDGER_TX_SIGNING_BYTES]; triple_entry_tx_signing_bytes(tx, bytes);
    determ_sha256(bytes, sizeof(bytes), out);
}
void k2_model_header(const k2_model_candidate_t *c, uint8_t out[K2_MODEL_HEADER_BYTES]) {
    determ_sha256_ctx hash; uint8_t body[32], id[32];
    determ_sha256_init(&hash); determ_sha256_update(&hash, &c->tx_count, 1);
    for(size_t i=0;i<c->tx_count && i<K2_MODEL_TXS;i++) { k2_model_tx_id(&c->txs[i],id); determ_sha256_update(&hash,id,32); }
    determ_sha256_final(&hash,body);
    memcpy(out,"K2MODEL1",8); memcpy(out+8,c->chain,32); be(out+40,c->shard,4);
    be(out+44,c->height,8); be(out+52,c->round,8); memcpy(out+60,c->parent,32);
    be(out+92,c->creators[0],2); be(out+94,c->creators[1],2); memcpy(out+96,body,32); be(out+128,c->variant,8);
}
void k2_model_id(const k2_model_candidate_t *c, uint8_t out[32]) {
    uint8_t header[K2_MODEL_HEADER_BYTES]; k2_model_header(c,header); determ_sha256(header,sizeof(header),out);
}
k2_model_status_t k2_model_init(k2_model_node_t *n, const k2_model_config_t *cfg) {
    if(!n || !cfg || cfg->local_pool_count<2 || cfg->local_pool_count>32 ||
       cfg->authority_count>K2_MODEL_CANDIDATES || cfg->receipt_count>K2_MODEL_RECEIPTS ||
       cfg->anchor_height>UINT64_MAX-K2_MODEL_DEPTH || cfg->anchor_state.account_count>LEDGER_MAX_ACCOUNTS)
        return K2_MODEL_INVALID;
    for(size_t i=0;i<cfg->authority_count;i++) {
        const k2_model_authority_t *a=&cfg->authority[i];
        if(a->creators[0]==a->creators[1] || a->creators[0]>=cfg->local_pool_count || a->creators[1]>=cfg->local_pool_count)
            return K2_MODEL_INVALID;
        for(size_t j=0;j<i;j++) {
            const k2_model_authority_t *b=&cfg->authority[j];
            if(a->height==b->height && a->round==b->round && !memcmp(a->parent,b->parent,32)) return K2_MODEL_INVALID;
        }
    }
    memset(n,0,sizeof(*n)); n->config=cfg; n->state=cfg->anchor_state; return K2_MODEL_OK;
}
static bool admissible(const k2_model_config_t *cfg,const k2_model_candidate_t *c) {
    bool authorized=false;
    if(c->tx_count>K2_MODEL_TXS || memcmp(c->chain,cfg->chain,32) || c->shard!=cfg->shard ||
       c->height<=cfg->anchor_height || c->height>cfg->anchor_height+K2_MODEL_DEPTH ||
       c->creators[0]==c->creators[1] || c->creators[0]>=cfg->local_pool_count || c->creators[1]>=cfg->local_pool_count) return false;
    for(size_t i=0;i<cfg->authority_count;i++) {
        const k2_model_authority_t *a=&cfg->authority[i];
        if(a->height==c->height && a->round==c->round && !memcmp(a->parent,c->parent,32) &&
           a->creators[0]==c->creators[0] && a->creators[1]==c->creators[1]) authorized=true;
    }
    if(!authorized) return false;
    for(size_t i=0;i<c->tx_count;i++) {
        uint8_t id[32], bytes[LEDGER_TX_SIGNING_BYTES]; bool shared=false;
        k2_model_tx_id(&c->txs[i],id);
        for(size_t j=0;j<i;j++) { uint8_t other[32]; k2_model_tx_id(&c->txs[j],other); if(!memcmp(id,other,32)) return false; }
        uint32_t required=(UINT32_C(1)<<c->creators[0])|(UINT32_C(1)<<c->creators[1]);
        for(size_t j=0;j<cfg->receipt_count;j++)
            if(!memcmp(id,cfg->receipts[j].tx_id,32) && (cfg->receipts[j].received_by&required)==required) shared=true;
        if(!shared) return false;
        triple_entry_tx_signing_bytes(&c->txs[i],bytes);
        if(determ_ed25519_verify(c->txs[i].from,bytes,sizeof(bytes),c->txs[i].sig)!=0) return false;
    }
    return true;
}
static int find_record(const k2_model_node_t *n,const uint8_t id[32]) {
    for(size_t i=0;i<n->record_count;i++) if(!memcmp(n->records[i].id,id,32)) return (int)i;
    return -1;
}
/* Replay on the candidate's own ancestry; unselected does not mean invalid. */
static k2_model_status_t replay_record(const k2_model_node_t *n,size_t at,ledger_state_t *state) {
    size_t path[K2_MODEL_DEPTH], count=0; uint64_t expected=n->records[at].candidate.height;
    for(;;) {
        const k2_model_candidate_t *c=&n->records[at].candidate;
        if(count==K2_MODEL_DEPTH || c->height!=expected) return K2_MODEL_INVALID;
        path[count++]=at;
        if(!memcmp(c->parent,n->config->anchor_id,32)) {
            if(c->height!=n->config->anchor_height+1) return K2_MODEL_INVALID;
            break;
        }
        if(c->height==n->config->anchor_height+1) return K2_MODEL_INVALID;
        int parent=find_record(n,c->parent); if(parent<0) return K2_MODEL_PENDING;
        at=(size_t)parent; expected--;
    }
    *state=n->config->anchor_state;
    while(count) {
        const k2_model_candidate_t *c=&n->records[path[--count]].candidate;
        for(size_t i=0;i<c->tx_count;i++) if(ledger_apply_tx(state,&c->txs[i],0)!=LEDGER_OK) return K2_MODEL_INVALID;
    }
    return K2_MODEL_OK;
}
static bool selected_tx(const k2_model_node_t *n,const uint8_t id[32]) {
    for(size_t i=0;i<n->selected_count;i++) {
        const k2_model_candidate_t *c=&n->records[n->selected[i]].candidate;
        for(size_t j=0;j<c->tx_count;j++) { uint8_t tid[32]; k2_model_tx_id(&c->txs[j],tid); if(!memcmp(tid,id,32)) return true; }
    }
    return false;
}
static void requeue(k2_model_node_t *n,ledger_state_t *scratch) {
    const triple_entry_tx_t *txs[K2_MODEL_RECEIPTS]; uint8_t ids[K2_MODEL_RECEIPTS][32]; size_t count=0;
    n->requeue_count=0; n->rejected_requeue_count=0;
    for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid) {
        const k2_model_candidate_t *c=&n->records[i].candidate;
        for(size_t j=0;j<c->tx_count;j++) {
            uint8_t id[32]; bool duplicate=false; k2_model_tx_id(&c->txs[j],id);
            if(selected_tx(n,id)) continue;
            for(size_t k=0;k<count;k++) if(!memcmp(ids[k],id,32)) duplicate=true;
            if(duplicate) continue;
            size_t pos=count;
            while(pos && memcmp(ids[pos-1],id,32)>0) { memcpy(ids[pos],ids[pos-1],32); txs[pos]=txs[pos-1]; pos--; }
            memcpy(ids[pos],id,32); txs[pos]=&c->txs[j]; count++;
        }
    }
    for(size_t i=0;i<count;i++) {
        bool conflict=false; *scratch=n->state;
        if(ledger_apply_tx(scratch,txs[i],0)!=LEDGER_OK) { n->rejected_requeue_count++; continue; }
        for(size_t j=0;j<n->requeue_count;j++)
            if(!memcmp(n->requeue[j].from,txs[i]->from,32) && n->requeue[j].nonce==txs[i]->nonce) conflict=true;
        if(conflict) { n->rejected_requeue_count++; continue; }
        n->requeue[n->requeue_count++]=*txs[i];
    }
}
static k2_model_status_t recover(k2_model_node_t *n,ledger_state_t *scratch,size_t added) {
    k2_model_status_t added_status=K2_MODEL_PENDING;
    for(size_t i=0;i<n->record_count;i++) {
        k2_model_status_t status=replay_record(n,i,scratch);
        n->records[i].valid=status==K2_MODEL_OK;
        if(i==added) added_status=status;
    }
    if(added_status==K2_MODEL_INVALID) return K2_MODEL_INVALID;
    /* This model does not select between competing complete histories. */
    for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && memcmp(n->records[i].candidate.parent,n->config->anchor_id,32))
        for(size_t j=0;j<i;j++) if(n->records[j].valid && !memcmp(n->records[i].candidate.parent,n->records[j].candidate.parent,32))
            return K2_MODEL_UNSUPPORTED_BRANCHING;
    int best=-1;
    /* Transaction-hash preference is confined to assembly/requeue. Even
     * conflicting original-parent-valid siblings use this block ranking. */
    for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && !memcmp(n->records[i].candidate.parent,n->config->anchor_id,32)) {
        if(best<0 || n->records[i].candidate.tx_count>n->records[best].candidate.tx_count ||
           (n->records[i].candidate.tx_count==n->records[best].candidate.tx_count &&
            memcmp(n->records[i].header,n->records[best].header,K2_MODEL_HEADER_BYTES)<0)) best=(int)i;
    }
    n->selected_count=0; n->state=n->config->anchor_state;
    while(best>=0) {
        if(n->selected_count==K2_MODEL_DEPTH) return K2_MODEL_INVALID;
        n->selected[n->selected_count++]=(size_t)best;
        const k2_model_candidate_t *c=&n->records[best].candidate;
        for(size_t i=0;i<c->tx_count;i++) if(ledger_apply_tx(&n->state,&c->txs[i],0)!=LEDGER_OK) return K2_MODEL_INVALID;
        int child=-1;
        for(size_t i=0;i<n->record_count;i++) if(n->records[i].valid && !memcmp(n->records[i].candidate.parent,n->records[best].id,32)) child=(int)i;
        best=child;
    }
    requeue(n,scratch); return added_status;
}
k2_model_status_t k2_model_prepare(const k2_model_node_t *n,const k2_model_candidate_t *c,k2_model_workspace_t *w) {
    if(!n || !c || !w || !n->config) return K2_MODEL_INVALID;
    w->prepared=false;
    if(!admissible(n->config,c)) return K2_MODEL_INVALID;
    uint8_t id[32]; k2_model_id(c,id);
    if(find_record(n,id)>=0) return K2_MODEL_DUPLICATE;
    if(n->record_count==K2_MODEL_CANDIDATES || n->generation==UINT64_MAX) return K2_MODEL_FULL;
    w->next=*n; w->base_generation=n->generation; w->prepared_for=n;
    size_t added=w->next.record_count++;
    k2_model_record_t *record=&w->next.records[added]; memset(record,0,sizeof(*record)); record->candidate=*c;
    memcpy(record->id,id,32); k2_model_header(c,record->header);
    k2_model_status_t status=recover(&w->next,&w->replay,added);
    if(status<0) return status;
    w->next.generation++; w->prepared=true; return status;
}
k2_model_status_t k2_model_publish(k2_model_node_t *n,k2_model_workspace_t *w) {
    if(!n || !w || !w->prepared || w->prepared_for!=n || n->generation!=w->base_generation || n->config!=w->next.config) return K2_MODEL_STALE_PREPARATION;
    *n=w->next; w->prepared=false; return K2_MODEL_OK;
}
k2_model_status_t k2_model_receive(k2_model_node_t *n,const k2_model_candidate_t *c,k2_model_workspace_t *w) {
    k2_model_status_t status=k2_model_prepare(n,c,w);
    if(status<0 || status==K2_MODEL_DUPLICATE) return status;
    if(k2_model_publish(n,w)!=K2_MODEL_OK) return K2_MODEL_STALE_PREPARATION;
    return status;
}
k2_model_status_t k2_model_journal(const k2_model_node_t *n,uint8_t *out,size_t cap,size_t *written) {
    if(!n || !out || !written) return K2_MODEL_INVALID;
    size_t need=6;
    for(size_t i=0;i<n->record_count;i++) need+=2+K2_MODEL_HEADER_BYTES+1+n->records[i].candidate.tx_count*152;
    if(cap<need) return K2_MODEL_FULL;
    memcpy(out,"K2J1",4); be(out+4,n->record_count,2); size_t offset=6;
    for(size_t i=0;i<n->record_count;i++) {
        const k2_model_record_t *r=&n->records[i]; const k2_model_candidate_t *c=&r->candidate;
        size_t size=K2_MODEL_HEADER_BYTES+1+c->tx_count*152; be(out+offset,size,2); offset+=2;
        memcpy(out+offset,r->header,K2_MODEL_HEADER_BYTES); offset+=K2_MODEL_HEADER_BYTES; out[offset++]=c->tx_count;
        for(size_t j=0;j<c->tx_count;j++) {
            triple_entry_tx_signing_bytes(&c->txs[j],out+offset); offset+=88;
            memcpy(out+offset,c->txs[j].sig,64); offset+=64;
        }
    }
    *written=offset; return K2_MODEL_OK;
}
k2_model_status_t k2_model_restore(k2_model_node_t *out,const k2_model_config_t *cfg,const uint8_t *bytes,size_t len,k2_model_workspace_t *w) {
    if(!out || !cfg || out->config!=cfg || !bytes || !w || len<6 || memcmp(bytes,"K2J1",4)) return K2_MODEL_INVALID;
    if(out->generation==UINT64_MAX) return K2_MODEL_FULL;
    uint64_t next_generation=out->generation+1;
    size_t count=(size_t)read_be(bytes+4,2), offset=6;
    if(count>K2_MODEL_CANDIDATES || k2_model_init(&w->restoring,cfg)!=K2_MODEL_OK) return K2_MODEL_INVALID;
    for(size_t i=0;i<count;i++) {
        if(len-offset<2) return K2_MODEL_INVALID;
        size_t size=(size_t)read_be(bytes+offset,2); offset+=2;
        if(size>len-offset || size<K2_MODEL_HEADER_BYTES+1) return K2_MODEL_INVALID;
        const uint8_t *p=bytes+offset; k2_model_candidate_t c; memset(&c,0,sizeof(c));
        if(memcmp(p,"K2MODEL1",8)) return K2_MODEL_INVALID;
        memcpy(c.chain,p+8,32); c.shard=(uint32_t)read_be(p+40,4); c.height=read_be(p+44,8); c.round=read_be(p+52,8);
        memcpy(c.parent,p+60,32); c.creators[0]=(uint16_t)read_be(p+92,2); c.creators[1]=(uint16_t)read_be(p+94,2); c.variant=read_be(p+128,8);
        c.tx_count=p[K2_MODEL_HEADER_BYTES];
        if(c.tx_count>K2_MODEL_TXS || size!=K2_MODEL_HEADER_BYTES+1+c.tx_count*152) return K2_MODEL_INVALID;
        for(size_t j=0;j<c.tx_count;j++) {
            const uint8_t *tx=p+K2_MODEL_HEADER_BYTES+1+j*152;
            memcpy(c.txs[j].from,tx,32); memcpy(c.txs[j].to,tx+32,32);
            c.txs[j].amount=read_be(tx+64,8); c.txs[j].fee=read_be(tx+72,8); c.txs[j].nonce=read_be(tx+80,8); memcpy(c.txs[j].sig,tx+88,64);
        }
        uint8_t header[K2_MODEL_HEADER_BYTES]; k2_model_header(&c,header);
        if(memcmp(header,p,sizeof(header))) return K2_MODEL_INVALID;
        k2_model_status_t status=k2_model_receive(&w->restoring,&c,w);
        if(status<0 || status==K2_MODEL_DUPLICATE) return K2_MODEL_INVALID;
        offset+=size;
    }
    if(offset!=len) return K2_MODEL_INVALID;
    w->restoring.generation=next_generation;
    *out=w->restoring; return K2_MODEL_OK;
}
