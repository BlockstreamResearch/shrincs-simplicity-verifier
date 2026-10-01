#!/usr/bin/env python3
"""Negative tests: corrupt witness fields of a hand-written program and check that verification fails.
Usage: tamper.py prog.simpl spec.json [fixed]      (pass `fixed` for a --fixed-q program)
The harness binary is ../tools/harness/target/release/hand unless HAND_BIN is set."""
import copy, json, subprocess, sys, os
HERE = os.path.dirname(os.path.abspath(__file__))
prog, spec_path = sys.argv[1], sys.argv[2]
fixed = len(sys.argv) > 3 and sys.argv[3] == 'fixed'
spec = json.load(open(spec_path))
H = os.environ.get('HAND_BIN', os.path.join(HERE, '..', 'tools', 'harness', 'target', 'release', 'hand'))

def run(s):
    p = os.path.join(HERE, '.tamper_spec.json')
    json.dump(s, open(p, 'w'))
    out = subprocess.run([H, prog, p], capture_output=True, text=True).stdout.strip()
    try:
        return json.loads(out)
    except Exception:
        return {'ok': False, 'stage': 'crash', 'error': out[:120]}

def flip_hex(h, pos_nibble=0, delta=1):
    v = int(h[pos_nibble], 16) ^ delta
    return h[:pos_nibble] + f'{v:x}' + h[pos_nibble + 1:]

def get(d, path):
    for k in path: d = d[k]
    return d
def setp(d, path, val):
    for k in path[:-1]: d = d[k]
    d[path[-1]] = val

head = 'w_headq' if fixed else 'w_head'
cases = []
if fixed:
    # ((seed, root), (msg, (r, counter)))
    fields = {'seed': ['p', 0, 'p', 0, 'w'], 'root': ['p', 0, 'p', 1, 'w'], 'msg': ['p', 1, 'p', 0, 'w'], 'r': ['p', 1, 'p', 1, 'p', 0, 'w'], 'counter': ['p', 1, 'p', 1, 'p', 1, 'w']}
else:
    # ((seed, root), (keyidx, (msg, (r, counter))))
    fields = {'seed': ['p', 0, 'p', 0, 'w'], 'root': ['p', 0, 'p', 1, 'w'], 'keyidx': ['p', 1, 'p', 0, 'w'], 'msg': ['p', 1, 'p', 1, 'p', 0, 'w'],
              'r': ['p', 1, 'p', 1, 'p', 1, 'p', 0, 'w'], 'counter': ['p', 1, 'p', 1, 'p', 1, 'p', 1, 'w']}
for name, path in fields.items():
    for nib in (0, -1):
        s = copy.deepcopy(spec)
        h = get(s[head], path)
        setp(s[head], path, flip_hex(h, nib if nib >= 0 else len(h) - 1))
        cases.append((f'{name} nibble {nib}', s))
# signature elements
for i in (0, 1, 31, 63):
    for nib in (0, 31):
        s = copy.deepcopy(spec)
        s['w_sig']['w'] = flip_hex(s['w_sig']['w'], 32 * i + nib)
        cases.append((f'sig[{i}] nibble {nib}', s))
# path0, slroot
for name in ('w_path0', 'w_slroot'):
    s = copy.deepcopy(spec); s[name]['w'] = flip_hex(s[name]['w'], 5); cases.append((f'{name}', s))
# swap two signature elements
s = copy.deepcopy(spec); w = s['w_sig']['w']; s['w_sig']['w'] = w[32:64] + w[:32] + w[64:]; cases.append(('sig swap 0,1', s))
if not fixed:
    # option structure tampering
    if 'some' in spec['w_path1']:
        s = copy.deepcopy(spec); s['w_path1'] = {'none': {'w': 128}}; cases.append(('drop path1', s))
        s = copy.deepcopy(spec); s['w_path1']['some']['w'] = flip_hex(s['w_path1']['some']['w'], 3); cases.append(('path1 flipped', s))
    else:
        s = copy.deepcopy(spec); s['w_path1'] = {'some': s['w_path0']}; cases.append(('extra path1', s))
    if 'some' in spec['w_path2']:
        s = copy.deepcopy(spec); s['w_path2'] = {'none': {'w': 128}}; cases.append(('drop path2', s))
    # list: move an element / flip
    def walk(v, f):
        if 'p' in v: return {'p': [walk(v['p'][0], f), walk(v['p'][1], f)]}
        if 'some' in v: return {'some': {'w': f(v['some']['w'])}}
        return v
    s = copy.deepcopy(spec); s['w_list'] = walk(s['w_list'], lambda w: flip_hex(w, 7)); 
    if s['w_list'] != spec['w_list']: cases.append(('list element flipped', s))
    s = copy.deepcopy(spec); s['w_list'] = walk(s['w_list'], lambda w: w[32:] + w[:32])
    if s['w_list'] != spec['w_list']: cases.append(('list elements rotated', s))
else:
    if 'w_rest' in spec:
        def walk(v, f):
            if 'p' in v: return {'p': [walk(v['p'][0], f), walk(v['p'][1], f)]}
            return {'w': f(v['w'])}
        s = copy.deepcopy(spec); s['w_rest'] = walk(s['w_rest'], lambda w: flip_hex(w, 7)); cases.append(('rest element flipped', s))
        s = copy.deepcopy(spec); s['w_rest'] = walk(s['w_rest'], lambda w: w[32:] + w[:32] if len(w) > 32 else flip_hex(w, 0)); cases.append(('rest elements rotated', s))

base = run(spec)
assert base['ok'], base
rejected = 0
for name, s in cases:
    r = run(s)
    status = 'rejected' if not r['ok'] else 'ACCEPTED (BAD)'
    if not r['ok']: rejected += 1
    print(f'{name:28s} {status:16s} {r.get("stage","")} {r.get("error","")[:50]}')
print(f'{rejected}/{len(cases)} tampered witnesses rejected')
