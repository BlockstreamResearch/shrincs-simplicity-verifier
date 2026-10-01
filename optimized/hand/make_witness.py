#!/usr/bin/env python3
"""Emit witness specs (JSON, read by the `hand` harness) for the hand-written stateful verifier from vectors_full.jsonl.

Usage: make_witness.py vectors_full.jsonl outdir
Writes outdir/stateful_q<q>.hand.json for every stateful vector. Each file carries the witness values for both program
kinds (unused names are ignored by the harness):
  general program : w_head = ((seed, root), (key_idx, (message, (r, counter)))), w_sig = 64 x u128, w_path0,
                    w_path1 / w_path2 = Option<u128>, w_list = (Option<[u128;128]>, (..., Option<[u128;1]>)), w_slroot
  fixed-q program : w_headq = ((seed, root), (message, (r, counter))), w_sig, w_path0, w_rest = nested power-of-two
                    chunks of the remaining auth nodes (largest first), w_slroot
Value spec: {"w": hex} word, {"p": [a, b]} product, {"some": v} / {"none": {"w": bits}} option.
"""
import json, os, sys

LIST_LEVELS = [128, 64, 32, 16, 8, 4, 2, 1]

def W(hexstr): return {'w': hexstr}

def opt_list(path_rest):
    L = len(path_rest)
    assert L < 256
    chunks = []
    pos = 0
    for n in LIST_LEVELS:
        if L & n:
            chunks.append({'some': W(''.join(path_rest[pos:pos + n]))})
            pos += n
        else:
            chunks.append({'none': W(128 * n)})
    # nest: (opt128, (opt64, (..., (opt2, opt1))))
    v = chunks[-1]
    for c in reversed(chunks[:-1]):
        v = {'p': [c, v]}
    return v

def spec_for(rec, key):
    b = rec['sig']
    sl_root = b[:32]; r = b[32:96]; counter = b[96:104]
    sig = b[104:104 + 64 * 32]
    path_hex = b[104 + 64 * 32:]
    path = [path_hex[i:i + 32] for i in range(0, len(path_hex), 32)]
    def Pr(a, b): return {'p': [a, b]}
    s = {
        'w_head': Pr(Pr(W(key['seed']), W(key['root'])), Pr(W(f"{rec['q']:08x}"), Pr(W(rec['message']), Pr(W(r), W(counter))))),
        'w_seed': W(key['seed']), 'w_root': W(key['root']), 'w_keyidx': W(f"{rec['q']:08x}"),
        'w_msg': W(rec['message']), 'w_r': W(r), 'w_counter': W(counter), 'w_sig': W(sig),
        'w_path0': W(path[0]),
        'w_path1': {'some': W(path[1])} if len(path) > 1 else {'none': W(128)},
        'w_path2': {'some': W(path[2])} if len(path) > 2 else {'none': W(128)},
        'w_list': opt_list(path[3:]),
        'w_slroot': W(sl_root),
    }
    # fixed-q layout: head without key index, rest of the path as nested power-of-two chunks (largest first)
    s['w_headq'] = Pr(Pr(W(key['seed']), W(key['root'])), Pr(W(rec['message']), Pr(W(r), W(counter))))
    rest = path[1:]
    chunks = [n for n in LIST_LEVELS if len(rest) & n]
    pos = 0; vals = []
    for n in chunks:
        vals.append(W(''.join(rest[pos:pos + n]))); pos += n
    if vals:
        v = vals[-1]
        for c in reversed(vals[:-1]):
            v = Pr(c, v)
        s['w_rest'] = v
    return s

if __name__ == '__main__':
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    key = None; n = 0
    for line in open(src):
        rec = json.loads(line)
        if rec['kind'] == 'key':
            key = rec; continue
        if rec['kind'] != 'stateful':
            continue
        json.dump(spec_for(rec, key), open(os.path.join(outdir, f"stateful_q{rec['q']}.hand.json"), 'w'))
        n += 1
    print(f'wrote {n} witness specs to {outdir}')
