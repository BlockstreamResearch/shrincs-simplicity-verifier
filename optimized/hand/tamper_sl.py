#!/usr/bin/env python3
"""Negative tests for the hand-written stateless verifier: corrupt witness fields and check that verification fails.
Usage: tamper_sl.py prog.simpl spec.json      (harness: ../tools/harness/target/release/hand or HAND_BIN)"""
import copy, json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
H = os.environ.get('HAND_BIN', os.path.join(HERE, '..', 'tools', 'harness', 'target', 'release', 'hand'))
prog, spec_path = sys.argv[1], sys.argv[2]
spec = json.load(open(spec_path))

def run(s):
    p = os.path.join(HERE, '.tamper_spec_sl.json')
    json.dump(s, open(p, 'w'))
    out = subprocess.run([H, prog, p], capture_output=True, text=True).stdout.strip()
    try:
        return json.loads(out)
    except Exception:
        return {'ok': False, 'stage': 'crash', 'error': out[:120]}

def flip_hex(h, pos=0):
    v = int(h[pos], 16) ^ 1
    return h[:pos] + f'{v:x}' + h[pos + 1:]

def get(d, path):
    for k in path: d = d[k]
    return d
def setp(d, path, val):
    for k in path[:-1]: d = d[k]
    d[path[-1]] = val

def leaves(v, out):
    """collect (container, key) of every tagged element below v, in order"""
    if 'p' in v:
        leaves(v['p'][0], out); leaves(v['p'][1], out)
    elif 'l' in v or 'r' in v:
        out.append(v)
    return out

cases = []
# head: ((seed, root), (message, r))
for name, path in {'seed': ['p', 0, 'p', 0, 'w'], 'root': ['p', 0, 'p', 1, 'w'], 'message': ['p', 1, 'p', 0, 'w'], 'r': ['p', 1, 'p', 1, 'w']}.items():
    for pos in (0, -1):
        s = copy.deepcopy(spec); h = get(s['w_head'], path); setp(s['w_head'], path, flip_hex(h, pos if pos >= 0 else len(h) - 1)); cases.append((f'{name} nibble {pos}', s))
s = copy.deepcopy(spec); s['w_slroot']['w'] = flip_hex(s['w_slroot']['w'], 3); cases.append(('uxmss root', s))
# FORS trees: secret, auth nodes, tags, swapped trees
for t in (0, 2, 4):
    s = copy.deepcopy(spec); s[f'w_fors{t}']['p'][0]['w'] = flip_hex(s[f'w_fors{t}']['p'][0]['w'], 7); cases.append((f'fors{t} sk', s))
    els = leaves(spec[f'w_fors{t}']['p'][1], [])
    for i in (0, 10, 21):
        s = copy.deepcopy(spec); el = leaves(s[f'w_fors{t}']['p'][1], [])[i]
        k = 'l' if 'l' in el else 'r'; el[k]['w'] = flip_hex(el[k]['w'], 5); cases.append((f'fors{t} node {i}', s))
        s = copy.deepcopy(spec); el = leaves(s[f'w_fors{t}']['p'][1], [])[i]
        k = 'l' if 'l' in el else 'r'; el['r' if k == 'l' else 'l'] = el.pop(k); cases.append((f'fors{t} node {i} tag flipped', s))
s = copy.deepcopy(spec); s['w_fors0'], s['w_fors1'] = s['w_fors1'], s['w_fors0']; cases.append(('fors trees 0/1 swapped', s))
# XMSS layers: counter, chain elements, auth nodes, tags, swapped layers
for layer in (0, 1):
    w = f'w_x{layer}'
    s = copy.deepcopy(spec); s[w]['p'][0]['w'] = flip_hex(s[w]['p'][0]['w'], 7); cases.append((f'x{layer} counter', s))
    for i in (0, 33, 63):
        s = copy.deepcopy(spec); s[w]['p'][1]['p'][0]['w'] = flip_hex(s[w]['p'][1]['p'][0]['w'], 32 * i + 9); cases.append((f'x{layer} sig[{i}]', s))
    for i in (0, 5, 11):
        s = copy.deepcopy(spec); el = leaves(s[w]['p'][1]['p'][1], [])[i]
        k = 'l' if 'l' in el else 'r'; el[k]['w'] = flip_hex(el[k]['w'], 5); cases.append((f'x{layer} node {i}', s))
        s = copy.deepcopy(spec); el = leaves(s[w]['p'][1]['p'][1], [])[i]
        k = 'l' if 'l' in el else 'r'; el['r' if k == 'l' else 'l'] = el.pop(k); cases.append((f'x{layer} node {i} tag flipped', s))
s = copy.deepcopy(spec); s['w_x0'], s['w_x1'] = s['w_x1'], s['w_x0']; cases.append(('xmss layers swapped', s))
s = copy.deepcopy(spec); sg = s['w_x0']['p'][1]['p'][0]['w']; s['w_x0']['p'][1]['p'][0]['w'] = sg[32:64] + sg[:32] + sg[64:]; cases.append(('x0 sig elements 0/1 swapped', s))

base = run(spec)
assert base['ok'], base
rejected = 0
for name, s in cases:
    r = run(s)
    bad = r['ok']
    rejected += not bad
    print(f'{name:30s} {"rejected" if not bad else "ACCEPTED (BAD)":16s} {r.get("stage", "")} {r.get("error", "")[:40]}')
print(f'{rejected}/{len(cases)} tampered witnesses rejected')
