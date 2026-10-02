#!/usr/bin/env python3
"""Emit witness specs (JSON, read by the `hand` harness) for the hand-written stateless verifier.

Usage: make_witness_sl.py vectors.jsonl outdir
Writes outdir/stateless_<n>.hand.json for every stateless vector in the file.

Witness layout (see gen_stateless_dag.py): w_head = ((seed, root), (message, r)); w_fors0..4 = (sk, (A16, (A4, A2)));
w_x0 / w_x1 = (counter, (sig, (A8, A4))); w_slroot. Auth-path nodes are tagged with
their side: Left(node) when the node already in hand is the left child (index bit 0), Right(node) otherwise.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ref_verify_sl as rv

def W(hexstr): return {'w': hexstr}
def Pr(a, b): return {'p': [a, b]}
T128 = {'w': 128}

def tagged(node_hex, bit):
    return {'r': W(node_hex), 't': T128} if bit else {'l': W(node_hex), 't': T128}

def balanced(items):
    assert len(items) & (len(items) - 1) == 0
    while len(items) > 1:
        items = [Pr(items[i], items[i + 1]) for i in range(0, len(items), 2)]
    return items[0]

def chunks(items, sizes):
    """nested (A_c0, (A_c1, ... A_ck)) of balanced chunks"""
    parts = []
    pos = 0
    for n in sizes:
        parts.append(balanced(items[pos:pos + n])); pos += n
    assert pos == len(items)
    v = parts[-1]
    for c in reversed(parts[:-1]):
        v = Pr(c, v)
    return v

def spec_for(rec, key):
    v = rv.parse_vector(rec, key)
    trace = {}
    ok, _ = rv.verify_stateless(**v, trace=trace)
    assert ok, 'vector does not verify'
    seed, root = key['seed'], key['root']
    s = {'w_head': Pr(Pr(W(seed), W(root)), Pr(W(rec['message']), W(v['r'].hex()))),
         'w_slroot': W(v['sf_root'].hex())}
    trees = []
    for t in range(rv.K_TREES):
        sk, path = v['fors'][t]
        bits = trace['fors'][t]['bits']
        elems = [tagged(path[h].hex(), bits[h]) for h in range(rv.A)]
        trees.append(Pr(W(sk.hex()), chunks(elems, [16, 4, 2])))
    for t in range(rv.K_TREES):
        s[f'w_fors{t}'] = trees[t]
    for layer in range(rv.D_LAYERS):
        counter, sig, path = v['layers'][layer]
        bits = trace['xmss'][layer]['bits']
        elems = [tagged(path[h].hex(), bits[h]) for h in range(rv.H_XMSS)]
        s[f'w_x{layer}'] = Pr(W(f'{counter:08x}'), Pr(W(''.join(e.hex() for e in sig)), chunks(elems, [8, 4])))
    return s

if __name__ == '__main__':
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    key = None; n = 0
    for line in open(src):
        rec = json.loads(line)
        if rec['kind'] == 'key':
            key = rec; continue
        if rec['kind'] != 'stateless':
            continue
        json.dump(spec_for(rec, key), open(os.path.join(outdir, f'stateless_{n}.hand.json'), 'w'))
        n += 1
    print(f'wrote {n} stateless witness specs to {outdir}')
