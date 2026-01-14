#!/usr/bin/env python3
import sys, os, struct, zipfile

fn = sys.argv[1]
offs = int(sys.argv[2])

def read_lfh_span(fp, lho, comp_size):
    fp.seek(lho)
    sig = struct.unpack("<I", fp.read(4))[0]
    if sig != 0x04034B50:  # PK\x03\x04
        return None
    fixed = fp.read(26)
    if len(fixed) != 26:
        return None
    _ver, flg, meth, _t, _d, _crc, _cs, _us, nlen, xlen = struct.unpack("<HHHHHIIIHH", fixed)
    name = fp.read(nlen)
    fp.read(xlen)
    data_start = lho + 30 + nlen + xlen
    data_end = data_start + comp_size - 1 if comp_size > 0 else data_start - 1
    return (flg, meth, name.decode('utf-8','replace'), data_start, data_end, nlen, xlen)

with zipfile.ZipFile(fn, 'r') as zf, open(fn, 'rb') as fh:
    print(f"[file] {fn}\n[offset] {offs}")
    hits = []
    lfh_meta_spans = []
    for zi in zf.infolist():
        lho = getattr(zi, "header_offset", 0) or 0
        span = read_lfh_span(fh, lho, zi.compress_size)
        if not span:
            continue
        flg, meth, name, ds, de, nlen, xlen = span
        # record LFH metadata span [lho .. ds-1]
        if ds > lho:
            lfh_meta_spans.append((lho, ds-1, name))
        role = None
        if ds <= offs <= de:
            role = "MEMBER_DATA"
        elif lho <= offs <= max(lho, ds-1):
            role = "LFH_METADATA"
        if role:
            hits.append((role, name, lho, ds, de, flg))
    # Check for DD windows (32B after member end)
    dd_hits = []
    file_len = os.path.getsize(fn)
    for zi in zf.infolist():
        lho = getattr(zi, "header_offset", 0) or 0
        span = read_lfh_span(fh, lho, zi.compress_size)
        if not span:
            continue
        flg, meth, name, ds, de, nlen, xlen = span
        if (flg & 0x0008) != 0:  # data descriptor present
            dd0 = de + 1
            dd1 = min(dd0 + 32, file_len-1)
            if dd0 <= offs <= dd1:
                dd_hits.append((name, dd0, dd1))
    # Print classification
    if hits:
        for role, name, lho, ds, de, flg in hits:
            print(f"[HIT] {role} in '{name}'  LHO={lho}  data=[{ds}..{de}]  flag_bits=0x{flg:04x}")
    elif dd_hits:
        for name, dd0, dd1 in dd_hits:
            print(f"[HIT] DATA_DESCRIPTOR after '{name}'  dd=[{dd0}..{dd1}]")
    else:
        # maybe between entries entirely: check nearest LFH meta spans
        near = [(abs((m0+m1)//2 - offs), m0, m1, nm) for (m0,m1,nm) in lfh_meta_spans]
        near.sort()
        nei = near[0] if near else None
        print("[HIT] GAP (not inside any member or LFH meta or DD)")
        if nei:
            print(f"      nearest LFH meta: '{nei[3]}' [{nei[1]}..{nei[2]}]")
