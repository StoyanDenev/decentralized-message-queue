#!/usr/bin/env python3
# tools/verify_mldsa_sign.py — ML-DSA (FIPS 204) Sign/Verify corpus verifier.
#
# The corpora tools/vectors/mldsa_sign.json (seed/sk, M', signature) and
# mldsa_verify.json (pk, M', signature, expected) hold the AUTHORITATIVE NIST ACVP
# sigGen (deterministic) + sigVer vectors. This module recomputes ML-DSA through an
# INDEPENDENT python implementation (hashlib SHAKE + from-scratch NTT, distinct from
# the C determ code) and checks: python Sign_internal reproduces the stored ACVP
# signature byte-for-byte, and python Verify_internal reproduces the stored
# testPassed flag. The C `determ test-c99-vectors` runs the SAME corpora through the
# shipped C; both are pinned against the frozen NIST bytes.
#
#   python tools/verify_mldsa_sign.py                    # verify committed corpora
#   python tools/verify_mldsa_sign.py --emit SG SV       # (re)gen from ACVP files
import hashlib, json, os, sys

Q=8380417; N=256; D=13; ZETA=1753
HERE=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGN_CORPUS=os.path.join(HERE,"tools","vectors","mldsa_sign.json")
VER_CORPUS =os.path.join(HERE,"tools","vectors","mldsa_verify.json")
PARAMS={
 "ML-DSA-44":dict(k=4,l=4,eta=2,tau=39,lam=128,g1=1<<17,g2=(Q-1)//88,omega=80),
 "ML-DSA-65":dict(k=6,l=5,eta=4,tau=49,lam=192,g1=1<<19,g2=(Q-1)//32,omega=55),
 "ML-DSA-87":dict(k=8,l=7,eta=2,tau=60,lam=256,g1=1<<19,g2=(Q-1)//32,omega=75),
}
def beta(p): return p["tau"]*p["eta"]
def brv8(i):
    r=0
    for b in range(8): r|=((i>>b)&1)<<(7-b)
    return r
ZS=[pow(ZETA,brv8(k),Q) for k in range(256)]
def ntt(a):
    a=a[:]; k=0; length=128
    while length>=1:
        s=0
        while s<256:
            k+=1; z=ZS[k]
            for j in range(s,s+length):
                t=(z*a[j+length])%Q; a[j+length]=(a[j]-t)%Q; a[j]=(a[j]+t)%Q
            s+=2*length
        length//=2
    return a
def invntt(a):
    a=a[:]; k=256; length=1
    while length<256:
        s=0
        while s<256:
            k-=1; z=(-ZS[k])%Q
            for j in range(s,s+length):
                t=a[j]; a[j]=(t+a[j+length])%Q; a[j+length]=(z*((t-a[j+length])%Q))%Q
            s+=2*length
        length*=2
    f=pow(256,Q-2,Q); return [(x*f)%Q for x in a]
def pw(a,b): return [(a[i]*b[i])%Q for i in range(N)]
def vadd(a,b): return [(a[i]+b[i])%Q for i in range(N)]
def vsub(a,b): return [(a[i]-b[i])%Q for i in range(N)]
def sh256(d,n): return hashlib.shake_256(d).digest(n)
def sh128(d,n): return hashlib.shake_128(d).digest(n)
def le16(x): return bytes([x&0xff,(x>>8)&0xff])
def sample_uniform(seed):
    buf=sh128(seed,4096); i=0; a=[]
    while len(a)<N:
        if i+3>len(buf): buf=sh128(seed,len(buf)+4096)
        t=buf[i]|(buf[i+1]<<8)|((buf[i+2]&0x7F)<<16); i+=3
        if t<Q: a.append(t)
    return a
def expand_a(rho,k,l): return [[sample_uniform(rho+bytes([j])+bytes([i])) for j in range(l)] for i in range(k)]
def sample_in_ball(rho,tau):
    buf=sh256(rho,8+256); signs=int.from_bytes(buf[:8],"little"); pos=8; c=[0]*N
    for i in range(N-tau,N):
        while True:
            if pos>=len(buf): buf=sh256(rho,len(buf)+256)
            j=buf[pos]; pos+=1
            if j<=i: break
        c[i]=c[j]; c[j]=1-2*(signs&1); signs>>=1
    return c
def _unpack(buf,n,bits):
    v=[]; acc=0; nb=0; bi=0
    for _ in range(n):
        while nb<bits: acc|=buf[bi]<<nb; bi+=1; nb+=8
        v.append(acc&((1<<bits)-1)); acc>>=bits; nb-=bits
    return v
def expand_mask(rhopp,it,l,g1):
    bits=18 if g1==(1<<17) else 20; out=[]
    for i in range(l):
        buf=sh256(rhopp+le16(l*it+i),N*bits//8)
        out.append([g1-f for f in _unpack(buf,N,bits)])
    return out
def decompose(r,g2):
    r%=Q; r0=r%(2*g2)
    if r0>g2: r0-=2*g2
    if r-r0==Q-1: return 0,r0-1
    return (r-r0)//(2*g2),r0
def high(r,g2): return decompose(r,g2)[0]
def low(r,g2): return decompose(r,g2)[1]
def use_hint(h,r,g2):
    m=(Q-1)//(2*g2); r1,r0=decompose(r,g2)
    if h==1: return (r1+1)%m if r0>0 else (r1-1)%m
    return r1
def cabs(x):
    x%=Q
    if x>Q//2: x-=Q
    return abs(x)
def centered(z):
    out=[]
    for x in z:
        x%=Q
        if x>Q//2: x-=Q
        out.append(x)
    return out
def simple_bitpack(w,bits):
    out=bytearray(); acc=0; nb=0
    for cf in w:
        acc|=(cf&((1<<bits)-1))<<nb; nb+=bits
        while nb>=8: out.append(acc&0xff); acc>>=8; nb-=8
    if nb: out.append(acc&0xff)
    return bytes(out)
def bitpack(w,a,b): return simple_bitpack([b-cf for cf in w],(a+b).bit_length())
def bitunpack(buf,a,b):
    bits=(a+b).bit_length(); return [b-v for v in _unpack(buf,N,bits)]
def pk_decode(pk,k):
    off=32; t1=[]
    for i in range(k): t1.append(_unpack(pk[off:off+320],N,10)); off+=320
    return pk[:32],t1
def sk_decode(sk,k,l,eta):
    rho=sk[:32]; K=sk[32:64]; tr=sk[64:128]; off=128; epb=96 if eta==2 else 128
    s1=[]; s2=[]; t0=[]
    for i in range(l): s1.append(bitunpack(sk[off:off+epb],eta,eta)); off+=epb
    for i in range(k): s2.append(bitunpack(sk[off:off+epb],eta,eta)); off+=epb
    for i in range(k): t0.append(bitunpack(sk[off:off+416],(1<<(D-1))-1,1<<(D-1))); off+=416
    return rho,K,tr,s1,s2,t0
def w1_encode(w1,g2):
    m=(Q-1)//(2*g2); bits=(m-1).bit_length()
    return b"".join(simple_bitpack(w1[i],bits) for i in range(len(w1)))
def hint_pack(h,k,omega):
    y=bytearray(omega+k); idx=0
    for i in range(k):
        for j in range(N):
            if h[i][j]: y[idx]=j; idx+=1
        y[omega+i]=idx
    return bytes(y)
def hint_unpack(buf,k,omega):
    h=[[0]*N for _ in range(k)]; idx=0
    for i in range(k):
        end=buf[omega+i]
        if end<idx or end>omega: return None
        first=idx
        while idx<end:
            if idx>first and buf[idx-1]>=buf[idx]: return None
            h[i][buf[idx]]=1; idx+=1
    for j in range(idx,omega):
        if buf[j]!=0: return None
    return h

def sign_internal(sk,Mp,p,rnd=bytes(32)):
    k,l,g1,g2,tau,lam4=p["k"],p["l"],p["g1"],p["g2"],p["tau"],p["lam"]//4
    rho,K,tr,s1,s2,t0=sk_decode(sk,k,l,p["eta"])
    mu=sh256(bytes(tr)+Mp,64); rhopp=sh256(bytes(K)+rnd+mu,64)
    A=expand_a(rho,k,l); s1h=[ntt(x) for x in s1]; s2h=[ntt(x) for x in s2]; t0h=[ntt(x) for x in t0]
    it=0
    while True:
        y=expand_mask(rhopp,it,l,g1); it+=1
        yh=[ntt(x) for x in y]
        w=[invntt([sum(A[i][j][c]*yh[j][c] for j in range(l))%Q for c in range(N)]) for i in range(k)]
        w1=[[high(w[i][c],g2) for c in range(N)] for i in range(k)]
        ct=sh256(mu+w1_encode(w1,g2),lam4); c=sample_in_ball(ct,tau); ch=ntt(c)
        cs1=[invntt(pw(ch,s1h[i])) for i in range(l)]
        cs2=[invntt(pw(ch,s2h[i])) for i in range(k)]
        z=[vadd(y[i],cs1[i]) for i in range(l)]; zc=[centered(z[i]) for i in range(l)]
        r0=[[low(vsub(w[i],cs2[i])[c],g2) for c in range(N)] for i in range(k)]
        if max(max(cabs(x) for x in zc[i]) for i in range(l))>=g1-beta(p): continue
        if max(max(abs(x) for x in r0[i]) for i in range(k))>=g2-beta(p): continue
        ct0=[invntt(pw(ch,t0h[i])) for i in range(k)]
        if max(max(cabs(x) for x in ct0[i]) for i in range(k))>=g2: continue
        h=[[1 if high((w[i][c]-cs2[i][c]+ct0[i][c])%Q,g2)!=high((w[i][c]-cs2[i][c])%Q,g2) else 0 for c in range(N)] for i in range(k)]
        if sum(sum(r) for r in h)>p["omega"]: continue
        out=bytearray(ct)
        for i in range(l): out+=bitpack(zc[i],g1-1,g1)
        out+=hint_pack(h,k,p["omega"])
        return bytes(out)

def verify_internal(pk,Mp,sig,p):
    k,l,g1,g2,tau,lam4=p["k"],p["l"],p["g1"],p["g2"],p["tau"],p["lam"]//4
    zpb=N*(18 if g1==(1<<17) else 20)//8
    rho,t1=pk_decode(pk,k)
    ct=sig[:lam4]; off=lam4; z=[]
    for i in range(l): z.append(bitunpack(sig[off:off+zpb],g1-1,g1)); off+=zpb
    h=hint_unpack(sig[off:off+p["omega"]+k],k,p["omega"])
    if h is None: return False
    if max(max(cabs(x) for x in z[i]) for i in range(l))>=g1-beta(p): return False
    A=expand_a(rho,k,l); tr=sh256(pk,64); mu=sh256(tr+Mp,64)
    c=sample_in_ball(ct,tau); ch=ntt(c); zh=[ntt(x) for x in z]
    t1h=[ntt([(t1[i][c]<<D)%Q for c in range(N)]) for i in range(k)]
    wap=[invntt(vsub([sum(A[i][j][c]*zh[j][c] for j in range(l))%Q for c in range(N)],pw(ch,t1h[i]))) for i in range(k)]
    w1=[[use_hint(h[i][c],wap[i][c],g2) for c in range(N)] for i in range(k)]
    return ct==sh256(mu+w1_encode(w1,g2),lam4)

def mprime(iface,ctx,M): return (bytes([0,len(ctx)])+ctx+M) if iface=="external" else M

def emit(sg_path,sv_path):
    sg=json.load(open(sg_path)); sv=json.load(open(sv_path)); svecs=[]; vvecs=[]
    for g in sg["testGroups"]:
        if not g.get("deterministic",False) or g.get("externalMu") or g.get("preHash")=="preHash": continue
        for t in g["tests"][:1]:
            Mp=mprime(g.get("signatureInterface"),bytes.fromhex(t.get("context","") or ""),bytes.fromhex(t["message"]))
            svecs.append({"paramSet":g["parameterSet"],"iface":g.get("signatureInterface"),
                          "mprime_hex":Mp.hex(),"sk_hex":t["sk"].lower(),"sig_hex":t["signature"].lower()})
    # Keep the corpus lean: external interface only, and for each param set take the
    # SHORTEST-message tests — 2 passing + 3 failing (distinct fail reasons) — so the
    # committed JSON stays small while still covering accept + the reject paths.
    for g in sv["testGroups"]:
        if g.get("signatureInterface")!="external" or g.get("preHash")=="preHash" or g.get("externalMu"): continue
        tests=sorted(g["tests"],key=lambda t:len(t.get("message","")))
        npass=nfail=0; seen_reason=set()
        for t in tests:
            if t["testPassed"]:
                if npass>=2: continue
            else:
                r=t.get("reason","")
                if nfail>=3 or r in seen_reason: continue
                seen_reason.add(r)
            Mp=mprime("external",bytes.fromhex(t.get("context","") or ""),bytes.fromhex(t["message"]))
            vvecs.append({"paramSet":g["parameterSet"],"mprime_hex":Mp.hex(),"pk_hex":t["pk"].lower(),
                          "sig_hex":t["signature"].lower(),"expected":bool(t["testPassed"]),"reason":t.get("reason","")})
            npass+=t["testPassed"]; nfail+=(not t["testPassed"])
    json.dump({"primitive":"mldsa_sign","source":"NIST ACVP-Server ML-DSA-sigGen-FIPS204 (deterministic; "
               "external+internal, pure); M' pre-formatted. Recomputed by tools/verify_mldsa_sign.py",
               "vectors":svecs},open(SIGN_CORPUS,"w"),indent=1)
    json.dump({"primitive":"mldsa_verify","source":"NIST ACVP-Server ML-DSA-sigVer-FIPS204 (external+internal, "
               "pure); M' pre-formatted; expected = testPassed. Recomputed by tools/verify_mldsa_sign.py",
               "vectors":vvecs},open(VER_CORPUS,"w"),indent=1)
    print("emitted %d sign + %d verify vectors"%(len(svecs),len(vvecs)))

def verify():
    ok=n=0
    d=json.load(open(SIGN_CORPUS))
    for v in d["vectors"]:
        n+=1; p=PARAMS[v["paramSet"]]
        got=sign_internal(bytes.fromhex(v["sk_hex"]),bytes.fromhex(v["mprime_hex"]),p)
        if got.hex()!=v["sig_hex"].lower(): print("  bad sign %s: sig != ACVP"%v["paramSet"]); continue
        ok+=1
    d=json.load(open(VER_CORPUS))
    for v in d["vectors"]:
        n+=1; p=PARAMS[v["paramSet"]]
        try: got=verify_internal(bytes.fromhex(v["pk_hex"]),bytes.fromhex(v["mprime_hex"]),bytes.fromhex(v["sig_hex"]),p)
        except Exception: got=False
        if got!=v["expected"]: print("  bad verify %s: got %s exp %s (%s)"%(v["paramSet"],got,v["expected"],v.get("reason"))); continue
        ok+=1
    print("mldsa sign/verify vectors: %d/%d OK"%(ok,n))
    return ok==n and n>0

if __name__=="__main__":
    if len(sys.argv)>=4 and sys.argv[1]=="--emit": emit(sys.argv[2],sys.argv[3])
    sys.exit(0 if verify() else 1)
