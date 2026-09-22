/* SPDX-License-Identifier: Apache-2.0
 * Finite DSF model, not production block or election verification.
 * Two nodes, one common anchor, competing root siblings and unique descendants.
 */
#include "k2_recovery_model.h"
#include <determ/crypto/ed25519/ed25519.h>
#include <determ/crypto/sha2/sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while(0)
static k2_model_config_t cfg;
static k2_model_node_t a,b,c,before;
static k2_model_workspace_t work,other;
static uint8_t keys[8][32],seeds[8][32];
static k2_model_candidate_t low,high,low_child,high_child;
static uint8_t journal[K2_MODEL_JOURNAL_MAX],old_journal[K2_MODEL_JOURNAL_MAX];
static const uint64_t initial[8]={100,0,100,0,100,0,0,0};
static triple_entry_tx_t transaction(unsigned from,unsigned to,uint64_t amount,uint64_t nonce) {
    triple_entry_tx_t tx; uint8_t bytes[LEDGER_TX_SIGNING_BYTES]; memset(&tx,0,sizeof(tx));
    memcpy(tx.from,keys[from],32); memcpy(tx.to,keys[to],32); tx.amount=amount; tx.nonce=nonce;
    triple_entry_tx_signing_bytes(&tx,bytes);
    CHECK(determ_ed25519_sign(seeds[from],keys[from],bytes,sizeof(bytes),tx.sig)==0); return tx;
}
static void receipt(const triple_entry_tx_t *tx,uint32_t mask) {
    CHECK(cfg.receipt_count<K2_MODEL_RECEIPTS);
    k2_model_receipt_t *r=&cfg.receipts[cfg.receipt_count++]; k2_model_tx_id(tx,r->tx_id); r->received_by=mask;
}
static k2_model_candidate_t candidate(const uint8_t parent[32],uint64_t height,uint16_t first,uint64_t variant) {
    k2_model_candidate_t x; memset(&x,0,sizeof(x)); memcpy(x.chain,cfg.chain,32); x.shard=cfg.shard;
    memcpy(x.parent,parent,32); x.height=height; x.creators[0]=first; x.creators[1]=first+1; x.variant=variant; return x;
}
static void authorize(const k2_model_candidate_t *x) {
    CHECK(cfg.authority_count<K2_MODEL_CANDIDATES);
    k2_model_authority_t *rule=&cfg.authority[cfg.authority_count++];
    memcpy(rule->parent,x->parent,32); rule->height=x->height; rule->round=x->round;
    rule->creators[0]=x->creators[0]; rule->creators[1]=x->creators[1];
}
static void setup(void) {
    memset(&cfg,0,sizeof(cfg)); cfg.chain[0]=0x71; cfg.shard=3; cfg.anchor_id[0]=0xa0; cfg.local_pool_count=8;
    ledger_state_init(&cfg.anchor_state);
    for(unsigned i=0;i<8;i++) {
        memset(seeds[i],0,32); seeds[i][0]=(uint8_t)(i+1); determ_ed25519_pubkey_from_seed(seeds[i],keys[i]);
        CHECK(ledger_register_account(&cfg.anchor_state,keys[i],initial[i])!=NULL);
    }
    low=candidate(cfg.anchor_id,1,0,90); low.tx_count=1; low.txs[0]=transaction(0,1,20,1);
    high=candidate(cfg.anchor_id,1,0,1); high.tx_count=2;
    high.txs[0]=transaction(2,3,5,1); high.txs[1]=transaction(4,5,7,1);
    uint8_t id[32]; k2_model_id(&low,id); low_child=candidate(id,2,2,1); low_child.tx_count=1; low_child.txs[0]=transaction(1,6,12,1);
    k2_model_id(&high,id); high_child=candidate(id,2,4,1); high_child.tx_count=1; high_child.txs[0]=transaction(3,7,3,1);
    authorize(&low); authorize(&low_child); authorize(&high_child);
    receipt(&low.txs[0],0xff); receipt(&high.txs[0],0xff); receipt(&high.txs[1],0xff);
    receipt(&low_child.txs[0],0xff); receipt(&high_child.txs[0],0xff);
}
static unsigned account(const uint8_t pk[32]) {
    for(unsigned i=0;i<8;i++) if(!memcmp(keys[i],pk,32)) return i;
    CHECK(0); return 0;
}
/* Independent arithmetic oracle: no ledger_apply_tx and no model recovery calls. */
static void oracle(const k2_model_node_t *n) {
    uint64_t balances[8], nonces[8]={0}, fees=0; uint8_t parent[32];
    memcpy(balances,initial,sizeof(balances)); memcpy(parent,cfg.anchor_id,32);
    for(size_t h=0;h<n->selected_count;h++) {
        const k2_model_record_t *r=&n->records[n->selected[h]];
        CHECK(!memcmp(r->candidate.parent,parent,32)); CHECK(r->candidate.height==h+1);
        for(size_t j=0;j<r->candidate.tx_count;j++) {
            const triple_entry_tx_t *tx=&r->candidate.txs[j]; unsigned from=account(tx->from),to=account(tx->to);
            CHECK(tx->nonce==nonces[from]+1); CHECK(tx->amount<=UINT64_MAX-tx->fee);
            uint64_t debit=tx->amount+tx->fee; CHECK(debit<=balances[from]); CHECK(fees<=UINT64_MAX-tx->fee);
            balances[from]-=debit; CHECK(balances[to]<=UINT64_MAX-tx->amount); balances[to]+=tx->amount;
            nonces[from]++; fees+=tx->fee;
        }
        memcpy(parent,r->id,32);
    }
    CHECK(n->state.account_count==8); CHECK(n->state.total_fees==fees);
    uint64_t total=fees;
    for(unsigned i=0;i<8;i++) {
        CHECK(!memcmp(n->state.accounts[i].pubkey,keys[i],32));
        CHECK(n->state.accounts[i].balance==balances[i]); CHECK(n->state.accounts[i].nonce==nonces[i]); total+=balances[i];
    }
    CHECK(total==300);
}
static void receive(k2_model_node_t *n,const k2_model_candidate_t *x,int expected) {
    CHECK(k2_model_receive(n,x,&work)==expected); oracle(n);
}
static void equal_state(const k2_model_node_t *x,const k2_model_node_t *y) {
    CHECK(x->state.account_count==y->state.account_count && x->state.total_fees==y->state.total_fees);
    for(size_t i=0;i<x->state.account_count;i++) {
        CHECK(!memcmp(x->state.accounts[i].pubkey,y->state.accounts[i].pubkey,32));
        CHECK(x->state.accounts[i].balance==y->state.accounts[i].balance);
        CHECK(x->state.accounts[i].nonce==y->state.accounts[i].nonce);
    }
}
static void selected(const k2_model_node_t *n,const k2_model_candidate_t *x) {
    uint8_t id[32]; k2_model_id(x,id); CHECK(n->selected_count>0); CHECK(!memcmp(n->records[n->selected[0]].id,id,32));
}
static void test_split_heal(void) {
    setup(); CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK); CHECK(k2_model_init(&b,&cfg)==K2_MODEL_OK);
    /* Partition: the scheduler withholds the other root, not its winning status. */
    receive(&a,&low_child,K2_MODEL_PENDING); CHECK(a.selected_count==0);
    receive(&a,&low,K2_MODEL_OK); selected(&a,&low); CHECK(a.selected_count==2); CHECK(a.state.accounts[6].balance==12);
    receive(&b,&high,K2_MODEL_OK); receive(&b,&high_child,K2_MODEL_OK); selected(&b,&high);
    CHECK(a.state.accounts[6].balance!=b.state.accounts[6].balance); /* Actual split witness. */
    /* Heal and retransmit out of order; neither node gets the other's state. */
    receive(&a,&high_child,K2_MODEL_PENDING); receive(&a,&high,K2_MODEL_OK);
    receive(&b,&low_child,K2_MODEL_PENDING); receive(&b,&low,K2_MODEL_OK);
    selected(&a,&high); selected(&b,&high); CHECK(a.selected_count==2 && b.selected_count==2);
    equal_state(&a,&b);
    CHECK(a.state.accounts[0].balance==100 && a.state.accounts[1].balance==0 && a.state.accounts[6].balance==0);
    CHECK(a.state.accounts[3].balance==2 && a.state.accounts[7].balance==3);
    CHECK(a.requeue_count==1 && a.rejected_requeue_count==1);
    CHECK(!memcmp(a.requeue[0].from,keys[0],32)); /* Funding may be resent; unfunded spend cannot. */
    memcpy(&before,&a,sizeof(a)); receive(&a,&low_child,K2_MODEL_DUPLICATE); CHECK(!memcmp(&a,&before,sizeof(a)));
    /* The orphan retains its actual old parent and remains valid on that ancestry. */
    bool retained=false;
    for(size_t i=0;i<a.record_count;i++) if(!memcmp(a.records[i].candidate.parent,low_child.parent,32) && a.records[i].candidate.height==2)
        retained=a.records[i].valid;
    CHECK(retained);
}
static void test_same_body_header_and_restart(void) {
    setup(); high=low;
    /* Select a fixed reproducible witness where numeric-header and hash order
     * disagree. This is test data, not an election/randomness construction. */
    uint8_t low_id[32],high_id[32]; bool found=false; k2_model_id(&low,low_id);
    for(high.variant=0;high.variant<low.variant;high.variant++) {
        k2_model_id(&high,high_id);
        if(memcmp(high_id,low_id,32)>0) { found=true; break; }
    }
    CHECK(found);
    CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK);
    receive(&a,&low,K2_MODEL_OK); receive(&a,&low_child,K2_MODEL_OK);
    CHECK(a.state.accounts[6].balance==12); size_t old_len=0,new_len=0;
    CHECK(k2_model_journal(&a,old_journal,sizeof(old_journal),&old_len)==K2_MODEL_OK);
    CHECK(k2_model_init(&b,&cfg)==K2_MODEL_OK);
    receive(&b,&low,K2_MODEL_OK); receive(&b,&low_child,K2_MODEL_OK);
    memcpy(&before,&a,sizeof(a));
    CHECK(k2_model_prepare(&a,&high,&work)==K2_MODEL_OK);
    CHECK(k2_model_publish(&b,&work)==K2_MODEL_STALE_PREPARATION);
    CHECK(!memcmp(&a,&before,sizeof(a))); oracle(&a); oracle(&work.next);
    CHECK(k2_model_journal(&work.next,journal,sizeof(journal),&new_len)==K2_MODEL_OK);
    /* Crash before publication: visible state was the complete old history. */
    CHECK(k2_model_restore(&b,&cfg,old_journal,old_len,&other)==K2_MODEL_OK); oracle(&b); selected(&b,&low);
    /* Crash after recording new journal: replay derives the new history itself. */
    CHECK(k2_model_init(&c,&cfg)==K2_MODEL_OK);
    CHECK(k2_model_restore(&c,&cfg,journal,new_len,&other)==K2_MODEL_OK); oracle(&c); selected(&c,&high);
    CHECK(c.selected_count==1 && c.state.accounts[1].balance==20 && c.state.accounts[6].balance==0);
    CHECK(c.requeue_count==1 && c.rejected_requeue_count==0); /* Same-body orphan tx remains individually valid. */
    CHECK(k2_model_publish(&a,&work)==K2_MODEL_OK); oracle(&a); equal_state(&a,&c);
    memcpy(&before,&c,sizeof(c)); journal[6+2+96]^=1;
    CHECK(k2_model_restore(&c,&cfg,journal,new_len,&other)==K2_MODEL_INVALID); CHECK(!memcmp(&c,&before,sizeof(c)));
    journal[6+2+96]^=1;
    CHECK(k2_model_restore(&c,&cfg,journal,new_len-1,&other)==K2_MODEL_INVALID); CHECK(!memcmp(&c,&before,sizeof(c)));
    size_t untouched=123;
    CHECK(k2_model_journal(&a,journal,1,&untouched)==K2_MODEL_FULL && untouched==123);
}
static void test_admission_atomicity(void) {
    setup();
    k2_model_candidate_t bad=high; bad.tx_count=3; bad.txs[2]=transaction(0,1,1000,1); receipt(&bad.txs[2],0xff);
    k2_model_candidate_t one_sided=low; one_sided.txs[0]=transaction(2,3,19,1); receipt(&one_sided.txs[0],1);
    k2_model_candidate_t impossible=low; impossible.parent[0]^=1; impossible.round=1; authorize(&impossible);
    CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK); receive(&a,&low,K2_MODEL_OK); memcpy(&before,&a,sizeof(a));
    CHECK(k2_model_receive(&a,&bad,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    CHECK(k2_model_receive(&a,&one_sided,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    CHECK(k2_model_receive(&a,&impossible,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    bad=high; bad.tx_count=3; bad.txs[2]=bad.txs[0];
    CHECK(k2_model_receive(&a,&bad,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    bad=low; bad.txs[0].sig[0]^=1;
    CHECK(k2_model_receive(&a,&bad,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    bad=high; bad.creators[0]=2; bad.creators[1]=3;
    CHECK(k2_model_receive(&a,&bad,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    bad=high; bad.shard++;
    CHECK(k2_model_receive(&a,&bad,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    bad=high; bad.round++;
    CHECK(k2_model_receive(&a,&bad,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    receive(&a,&high,K2_MODEL_OK); memcpy(&before,&a,sizeof(a));
    /* Reparented descendant has the new parent's genuine pair but fails state replay. */
    bad=low_child; memcpy(bad.parent,high_child.parent,32); bad.creators[0]=4; bad.creators[1]=5;
    CHECK(k2_model_receive(&a,&bad,&work)==K2_MODEL_INVALID); CHECK(!memcmp(&a,&before,sizeof(a)));
    oracle(&a);
}
static void test_requeue_conflict_and_dedup(void) {
    setup();
    k2_model_candidate_t second=low, second_child; uint8_t parent[32]; second.variant++;
    k2_model_id(&second,parent); second_child=candidate(parent,2,4,1);
    second_child.tx_count=1; second_child.txs[0]=transaction(4,6,11,1);
    low_child.txs[0]=transaction(4,5,10,1);
    high.txs[0]=transaction(2,3,5,1); high.txs[1]=transaction(2,3,4,2);
    authorize(&second_child); receipt(&low_child.txs[0],0xff); receipt(&second_child.txs[0],0xff); receipt(&high.txs[1],0xff);
    CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK);
    receive(&a,&low,K2_MODEL_OK); receive(&a,&second,K2_MODEL_OK);
    receive(&a,&low_child,K2_MODEL_OK); receive(&a,&second_child,K2_MODEL_OK); receive(&a,&high,K2_MODEL_OK);
    selected(&a,&high); CHECK(a.requeue_count==2 && a.rejected_requeue_count==1);
    uint8_t first[32],last[32],want[32]; k2_model_tx_id(&low_child.txs[0],first); k2_model_tx_id(&second_child.txs[0],last);
    memcpy(want,memcmp(first,last,32)<0?first:last,32);
    size_t funding=0,conflicting=0;
    for(size_t i=0;i<a.requeue_count;i++) {
        uint8_t id[32]; k2_model_tx_id(&a.requeue[i],id);
        if(!memcmp(a.requeue[i].from,keys[0],32)) funding++;
        if(!memcmp(a.requeue[i].from,keys[4],32)) { conflicting++; CHECK(!memcmp(id,want,32)); }
        if(i) { uint8_t prior[32]; k2_model_tx_id(&a.requeue[i-1],prior); CHECK(memcmp(prior,id,32)<0); }
    }
    CHECK(funding==1 && conflicting==1); /* Repeated omission is deduplicated. */
}
static void test_unsupported_conflicting_roots(void) {
    setup(); k2_model_candidate_t conflict=low; conflict.txs[0]=transaction(0,1,19,1); receipt(&conflict.txs[0],0xff);
    CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK); CHECK(k2_model_init(&b,&cfg)==K2_MODEL_OK);
    receive(&a,&low,K2_MODEL_OK); receive(&b,&conflict,K2_MODEL_OK);
    memcpy(&before,&a,sizeof(a));
    CHECK(k2_model_receive(&a,&conflict,&work)==K2_MODEL_UNSUPPORTED_CONFLICT); CHECK(!memcmp(&a,&before,sizeof(a)));
    memcpy(&before,&b,sizeof(b));
    CHECK(k2_model_receive(&b,&low,&work)==K2_MODEL_UNSUPPORTED_CONFLICT); CHECK(!memcmp(&b,&before,sizeof(b)));
    CHECK(a.state.accounts[1].balance!=b.state.accounts[1].balance); /* No convergence claim outside model domain. */
}
static void test_restore_invalidates_preparation(void) {
    setup(); CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK); CHECK(k2_model_init(&b,&cfg)==K2_MODEL_OK);
    receive(&a,&low,K2_MODEL_OK); receive(&b,&high,K2_MODEL_OK);
    CHECK(a.generation==b.generation);
    size_t len=0; CHECK(k2_model_journal(&b,journal,sizeof(journal),&len)==K2_MODEL_OK);
    CHECK(k2_model_prepare(&a,&low_child,&work)==K2_MODEL_OK);
    CHECK(k2_model_restore(&a,&cfg,journal,len,&other)==K2_MODEL_OK); oracle(&a); selected(&a,&high);
    memcpy(&before,&a,sizeof(a));
    CHECK(k2_model_publish(&a,&work)==K2_MODEL_STALE_PREPARATION); CHECK(!memcmp(&a,&before,sizeof(a)));
}
static void test_capacity_and_ambiguity(void) {
    setup(); CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK);
    k2_model_candidate_t x=low;
    for(size_t i=0;i<K2_MODEL_CANDIDATES;i++) { x.variant=100+i; receive(&a,&x,K2_MODEL_OK); }
    memcpy(&before,&a,sizeof(a)); x.variant=1;
    CHECK(k2_model_receive(&a,&x,&work)==K2_MODEL_FULL); CHECK(!memcmp(&a,&before,sizeof(a)));
    setup(); CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK); receive(&a,&low,K2_MODEL_OK); receive(&a,&low_child,K2_MODEL_OK);
    memcpy(&before,&a,sizeof(a)); x=low_child; x.variant++;
    CHECK(k2_model_receive(&a,&x,&work)==K2_MODEL_UNSUPPORTED_BRANCHING); CHECK(!memcmp(&a,&before,sizeof(a)));
    /* Prepared state cannot overwrite intervening accepted input. */
    CHECK(k2_model_prepare(&a,&high,&work)==K2_MODEL_OK);
    x=low; x.variant=95; CHECK(k2_model_receive(&a,&x,&other)==K2_MODEL_OK); memcpy(&before,&a,sizeof(a));
    CHECK(k2_model_publish(&a,&work)==K2_MODEL_STALE_PREPARATION); CHECK(!memcmp(&a,&before,sizeof(a)));
}
static uint32_t rng(uint32_t *seed) { *seed^=*seed<<13; *seed^=*seed>>17; *seed^=*seed<<5; return *seed; }
static void trace_state(determ_sha256_ctx *trace,const k2_model_node_t *n) {
    uint8_t v=(uint8_t)n->selected_count; determ_sha256_update(trace,&v,1);
    for(size_t i=0;i<n->selected_count;i++) determ_sha256_update(trace,n->records[n->selected[i]].id,32);
    for(size_t i=0;i<8;i++) for(unsigned field=0;field<2;field++) {
        uint64_t value=field?n->state.accounts[i].nonce:n->state.accounts[i].balance; uint8_t encoded[8];
        for(size_t j=0;j<8;j++) encoded[7-j]=(uint8_t)(value>>(8*j));
        determ_sha256_update(trace,encoded,8);
    }
}
static void schedule(uint32_t seed,uint8_t out[32]) {
    CHECK(k2_model_init(&a,&cfg)==K2_MODEL_OK); CHECK(k2_model_init(&b,&cfg)==K2_MODEL_OK);
    const k2_model_candidate_t *pool[4]={&low,&high,&low_child,&high_child};
    size_t order[8]={0,1,2,3,4,5,6,7};
    for(size_t i=8;i>1;i--) { size_t j=rng(&seed)%i,t=order[i-1]; order[i-1]=order[j]; order[j]=t; }
    determ_sha256_ctx trace; determ_sha256_init(&trace);
    for(size_t i=0;i<8;i++) {
        k2_model_node_t *n=order[i]<4?&a:&b; const k2_model_candidate_t *x=pool[order[i]%4];
        int status=k2_model_receive(n,x,&work); CHECK(status==K2_MODEL_OK || status==K2_MODEL_PENDING); oracle(n); trace_state(&trace,n);
        CHECK(k2_model_receive(n,x,&work)==K2_MODEL_DUPLICATE); oracle(n);
    }
    selected(&a,&high); selected(&b,&high); CHECK(a.selected_count==2 && b.selected_count==2);
    equal_state(&a,&b); determ_sha256_final(&trace,out);
}
int main(void) {
    test_split_heal(); test_same_body_header_and_restart(); test_admission_atomicity(); test_capacity_and_ambiguity();
    test_requeue_conflict_and_dedup(); test_unsupported_conflicting_roots(); test_restore_invalidates_preparation();
    setup();
    for(uint32_t seed=1;seed<=8;seed++) { uint8_t first[32],second[32]; schedule(seed,first); schedule(seed,second); CHECK(!memcmp(first,second,32)); }
    puts("PASS: finite anchored DSF model, original-parent replay, atomic publication and journal restart");
    puts("Scope: frozen pair/receipt oracles; no production election, timeout, DH/VDF, whole-history or sharding proof");
    return 0;
}
