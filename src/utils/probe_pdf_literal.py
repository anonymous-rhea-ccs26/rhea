#!/usr/bin/env python3
import sys, re, zlib, math, mmap

PATH = sys.argv[1]
ABS_OFF = int(sys.argv[2])          # e.g. 43008 (FN)
RADIUS  = int(sys.argv[3]) if len(sys.argv) > 3 else 262144

def ascii_ratio(b):
    if not b: return 1.0
    return sum(1 for x in b if x in (9,10,13) or 32 <= x <= 126)/len(b)

def chi2_uniform(b):
    if not b: return float("inf")
    f=[0]*256
    for x in b: f[x]+=1
    n=len(b); exp=n/256.0; s=0.0
    for c in f:
        d=c-exp; s += (d*d)/(exp if exp>0 else 1.0)
    return s

def entropy(b):
    if not b: return 0.0
    from math import log2
    f=[0]*256
    for x in b: f[x]+=1
    n=len(b)
    return -sum((c/n)*log2(c/n) for c in f if c)

def zlib_cr(sample):
    if not sample: return 0.0
    s=sample[:2048]
    try:
        comp=zlib.compress(s,6)
        return len(comp)/len(s)
    except Exception:
        return 1.0

def looks_utf8_text(b, min_print=0.60):
    try:
        s=b.decode("utf-8","strict")
        pr=sum(1 for ch in s if ch in "\t\n\r" or (0x20 <= ord(ch) <= 0x7e))/max(1,len(s))
        return pr >= min_print
    except Exception:
        return False

def pdf_textop_hits(b):
    ops=[b"BT",b"ET",b"Tj",b"TJ",b"Tf",b"Td",b"Tm",b"Tr",b"Ts",b"Tw",b"Tc"]
    return sum(b.count(op) for op in ops)

def paren_balance_ok(b, limit=200_000):
    esc=False; bal=0
    L=min(len(b),limit)
    for i in range(L):
        c=b[i]
        if esc: esc=False; continue
        if c==0x5c: esc=True; continue
        if c==0x28: bal+=1
        elif c==0x29 and bal>0: bal-=1
    return bal < 32

def inflate_any(b, max_tries=8, want_ops=True):
    if not b or len(b)<32: return (False,None,[])
    hits=[]
    i=0; L=len(b)
    while i < L-2 and len(hits) < (max_tries*4):
        x=b[i]
        if x==0x78 and b[i+1] in (0x01,0x5E,0x9C,0xDA) and (((x<<8)|b[i+1])%31)==0:
            hits.append(i)
            if len(hits)>=max_tries: break
            i+=2; continue
        i+=1
    details=[]
    for off in hits[:max_tries]:
        try:
            out=zlib.decompress(b[off:])
            if not out: 
                details.append((off, "decompress-empty", 0,0,0,0,0))
                continue
            ar=ascii_ratio(out); ch=chi2_uniform(out); H=entropy(out); cr=zlib_cr(out)
            ops=pdf_textop_hits(out); has_bt=(out.find(b"BT")!=-1); has_et=(out.find(b"ET")!=-1)
            accept_text = looks_utf8_text(out) and ascii_ratio(out)>=0.60
            accept_ops  = (ops>=4 or (has_bt and has_et)) and paren_balance_ok(out) and ascii_ratio(out)>=0.45
            details.append((off, "ok", len(out), ar, ch, H, cr, ops, accept_text, accept_ops))
            if accept_text or (want_ops and accept_ops):
                return (True, out[:2048], details)
        except Exception as e:
            details.append((off, f"decompress-error:{type(e).__name__}", 0,0,0,0,0))
            continue
    return (False, None, details)

# ---- open file + find the literal body covering ABS_OFF ----
with open(PATH, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
    fsize=len(mm)
    a=max(0, ABS_OFF - RADIUS); b=min(fsize, ABS_OFF + RADIUS)
    buf=mm[a:b]; rel=ABS_OFF - a

    # Find enclosing object then stream bounds
    m_end = re.search(rb"endobj", buf[rel:])
    if not m_end: sys.exit("No endobj in window")
    end_idx = rel + m_end.start()
    start_obj = None
    for m in re.finditer(rb"\b\d+\s+\d+\s+obj\b", buf[:end_idx]):
        start_obj = m.start()
    if start_obj is None: sys.exit("No obj before offset")
    obj = buf[start_obj:end_idx]

    # Find stream..endstream in that object (raw payload)
    m_stream = re.search(rb"\bstream[\r\n]", obj)
    m_endstream = re.search(rb"\bendstream\b", obj)
    if not m_stream or not m_endstream or m_endstream.start()<=m_stream.end():
        sys.exit("No stream/endstream in object")
    raw = obj[m_stream.end():m_endstream.start()]

    # Tokenize just enough to find the literal/hex string that covers rel
    rel_in_obj = start_obj + (rel - start_obj)   # position within obj
    rel_in_stream = (rel - start_obj) - m_stream.end()
    i=0; L=len(raw); in_comment=False; in_lit=False; lit_depth=0; lit_esc=False; lit_s=-1
    in_hex=False; hex_s=-1
    zone=None; zstart=None
    while i<L:
        c=raw[i]; nxt=raw[i+1] if i+1<L else None
        if in_comment:
            if c in (10,13): in_comment=False
            i+=1; continue
        if in_lit:
            if lit_esc: lit_esc=False; i+=1; continue
            if c==0x5c: lit_esc=True; i+=1; continue
            if c==0x28: lit_depth+=1; i+=1; continue
            if c==0x29:
                lit_depth=max(0,lit_depth-1); i+=1
                if lit_depth==0:
                    if zone=="literal_string":
                        body=raw[zstart:i-1]
                        break
                    in_lit=False
                continue
            if zone is None and i >= rel_in_stream: zone="literal_string"; zstart=lit_s
            i+=1; continue
        if in_hex:
            if c==0x3e:
                if zone=="hex_string":
                    body=raw[zstart:i]
                    break
                in_hex=False; i+=1; continue
            if zone is None and i >= rel_in_stream: zone="hex_string"; zstart=hex_s
            i+=1; continue

        if c==0x25: in_comment=True; i+=1; continue
        if c==0x28: in_lit=True; lit_depth=1; lit_esc=False; lit_s=i+1
        elif c==0x3c:
            if nxt==0x3c: i+=2; continue
            in_hex=True; hex_s=i+1
        i+=1

    print("zone_at_offset:", zone)
    if zone in ("literal_string", "hex_string"):
        print("body_len:", len(body))
        # Basic stats on RAW body (pre-decode)
        print("raw_ascii_ratio:", ascii_ratio(body))
        print("raw_chi2:", chi2_uniform(body))
        print("raw_entropy:", entropy(body))
        print("raw_zlib_cr:", zlib_cr(body))
        # Inflate-any like the detector
        ok, sample, details = inflate_any(body, max_tries=8, want_ops=True)
        print("inflate_any_ok:", ok)
        for d in details[:8]:
            print("  hit:", d)
    else:
        print("No string token at this offset inside the stream.")
