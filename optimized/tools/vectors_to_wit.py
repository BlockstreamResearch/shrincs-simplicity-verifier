#!/usr/bin/env python3
"""Convert raw SHRINCS-L signatures (vectors.jsonl from gen.cpp) into
   (a) the original repo's witness format (single PROOF value) and
   (b) the optimized verifier's split witness format.

Usage: vectors_to_wit.py vectors.jsonl outdir
"""
import json, sys, os

N = 16
HSF = 206
L = 64
A = 22
K_VERIFIED = 5
H_PRIME = 12
D = 2

def u(h):           # hex string -> decimal literal
    return str(int(h, 16))

def chunks(h, size_bytes):
    n = size_bytes * 2
    return [h[i:i+n] for i in range(0, len(h), n)]

def arr(items):
    return '[' + ', '.join(items) + ']'

def parse_stateful(sig_hex, q):
    sl_root = sig_hex[:32]; p = 32
    r = sig_hex[p:p+64]; p += 64
    counter = sig_hex[p:p+8]; p += 8
    elems = chunks(sig_hex[p:p+L*32], N); p += L*32
    path_nodes = HSF if q > HSF else q
    path = chunks(sig_hex[p:p+path_nodes*32], N); p += path_nodes*32
    assert p == len(sig_hex), (p, len(sig_hex))
    return sl_root, r, counter, elems, path

def parse_stateless(sig_hex):
    sf_root = sig_hex[:32]; p = 32
    r = sig_hex[p:p+64]; p += 64
    parts = []
    for _ in range(K_VERIFIED):
        sk = sig_hex[p:p+32]; p += 32
        path = chunks(sig_hex[p:p+A*32], N); p += A*32
        parts.append((sk, path))
    layers = []
    for _ in range(D):
        xr = sig_hex[p:p+64]; p += 64
        xc = sig_hex[p:p+8]; p += 8
        xe = chunks(sig_hex[p:p+L*32], N); p += L*32
        xp = chunks(sig_hex[p:p+H_PRIME*32], N); p += H_PRIME*32
        layers.append((xr, xc, xe, xp))
    assert p == len(sig_hex), (p, len(sig_hex))
    return sf_root, r, parts, layers

ORIG_TYPE = "(u256, (u128, u128), Either<((u256, u32, [u128; 64]), List<u128, 512>, u32), ((u256, ([(u128, [u128; 22]); 4], [(u128, [u128; 22]); 1])), [((u256, u32, [u128; 64]), [u128; 12]); 2])>, u128)"
SPHINCS_TYPE = "((u256, ([(u128, [u128; 22]); 4], [(u128, [u128; 22]); 1])), [((u256, u32, [u128; 64]), [u128; 12]); 2])"

def zeros(n):
    return arr(['0'] * n)

def dummy_stateless_opt():
    z22 = arr(['0'] * 22)
    out = {}
    out['HEAD_SL'] = {'type': '((u128, u128), u256, u256)', 'value': '((0, 0), 0, 0)'}
    out['FORS'] = {'type': '[(u128, [u128; 22]); 5]', 'value': arr(['(0, ' + z22 + ')'] * 5)}
    for i in (0, 1):
        out[f'X{i}_COUNTER'] = {'type': 'u32', 'value': '0'}
        out[f'X{i}_SIG'] = {'type': '[u128; 64]', 'value': zeros(64)}
        out[f'X{i}_PATH'] = {'type': '[u128; 12]', 'value': zeros(12)}
    out['ROOT_PART_SL'] = {'type': 'u128', 'value': '0'}
    return out

def dummy_stateful_opt():
    out = {}
    out['HEAD'] = {'type': '((u128, u128), u32, u256, u256, u32)', 'value': '((0, 0), 0, 0, 0, 0)'}
    out['SIG'] = {'type': '[u128; 64]', 'value': zeros(64)}
    out['PATH0'] = {'type': 'u128', 'value': '0'}
    out['PATH'] = {'type': 'List<u128, 256>', 'value': 'list![]'}
    out['ROOT_PART'] = {'type': 'u128', 'value': '0'}
    return out

def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    key = None
    index = []
    for line in open(src):
        rec = json.loads(line)
        if rec['kind'] == 'key':
            key = rec
            continue
        seed, root = key['seed'], key['root']
        msg = rec['message']
        pk_str = f"({u(seed)}, {u(root)})"
        if rec['kind'] == 'stateful':
            q = rec['q']
            sl_root, r, counter, elems, path = parse_stateful(rec['sig'], q)
            name = f"stateful_q{q}"
            left = f"Left((({u(r)}, {u(counter)}, {arr([u(e) for e in elems])}), list![{', '.join(u(x) for x in path)}], {q}))"
            orig = {'PROOF': {'type': ORIG_TYPE, 'value': f"({u(msg)}, {pk_str}, {left}, {u(sl_root)})"}}
            opt = {'IS_STATEFUL': {'type': 'bool', 'value': 'true'}}
            opt['HEAD'] = {'type': '((u128, u128), u32, u256, u256, u32)', 'value': f"({pk_str}, {q}, {u(msg)}, {u(r)}, {u(counter)})"}
            opt['SIG'] = {'type': '[u128; 64]', 'value': arr([u(e) for e in elems])}
            opt['PATH0'] = {'type': 'u128', 'value': u(path[0])}
            opt['PATH'] = {'type': 'List<u128, 256>', 'value': 'list![' + ', '.join(u(x) for x in path[1:]) + ']'}
            opt['ROOT_PART'] = {'type': 'u128', 'value': u(sl_root)}
            opt.update(dummy_stateless_opt())
            meta = {'name': name, 'kind': 'stateful', 'q': q, 'sig_bytes': len(rec['sig']) // 2, 'cpp_verify': rec['cpp_verify']}
        else:
            sf_root, r, parts, layers = parse_stateless(rec['sig'])
            name = f"stateless_{len([i for i in index if i['kind']=='stateless'])}"
            part_strs = [f"({u(sk)}, {arr([u(x) for x in path])})" for sk, path in parts]
            layer_strs = [f"(({u(xr)}, {u(xc)}, {arr([u(e) for e in xe])}), {arr([u(x) for x in xp])})" for xr, xc, xe, xp in layers]
            right = f"Right((({u(r)}, ({arr(part_strs[:4])}, {arr(part_strs[4:])})), {arr(layer_strs)}))"
            orig = {'PROOF': {'type': ORIG_TYPE, 'value': f"({u(msg)}, {pk_str}, {right}, {u(sf_root)})"}}
            opt = {'IS_STATEFUL': {'type': 'bool', 'value': 'false'}}
            opt.update(dummy_stateful_opt())
            opt['HEAD_SL'] = {'type': '((u128, u128), u256, u256)', 'value': f"({pk_str}, {u(msg)}, {u(r)})"}
            opt['FORS'] = {'type': '[(u128, [u128; 22]); 5]', 'value': arr(part_strs)}
            for i, (xr, xc, xe, xp) in enumerate(layers):
                opt[f'X{i}_COUNTER'] = {'type': 'u32', 'value': u(xc)}
                opt[f'X{i}_SIG'] = {'type': '[u128; 64]', 'value': arr([u(e) for e in xe])}
                opt[f'X{i}_PATH'] = {'type': '[u128; 12]', 'value': arr([u(x) for x in xp])}
            opt['ROOT_PART_SL'] = {'type': 'u128', 'value': u(sf_root)}
            meta = {'name': name, 'kind': 'stateless', 'sig_bytes': len(rec['sig']) // 2, 'cpp_verify': rec['cpp_verify']}
        json.dump(orig, open(os.path.join(outdir, name + '.orig.wit'), 'w'))
        json.dump(opt, open(os.path.join(outdir, name + '.opt.wit'), 'w'))
        index.append(meta)
    json.dump(index, open(os.path.join(outdir, 'index.json'), 'w'), indent=1)
    print(f"converted {len(index)} vectors into {outdir}")

main()
