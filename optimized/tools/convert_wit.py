#!/usr/bin/env python3
"""Convert the repo's single-value PROOF witness into the split witness layout used by the optimized verifier.

Usage: convert_wit.py <in.wit> <out.wit> [--list-bound N]
"""
import json, sys, re

def tokenize(s):
    return re.findall(r'list!|[A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+|[()\[\],]', s)

def parse(tokens, i=0):
    t = tokens[i]
    if t in ('Left', 'Right', 'Some'):
        assert tokens[i+1] == '('
        inner, i = parse(tokens, i+2)
        assert tokens[i] == ')'
        return (t, inner), i+1
    if t == 'None':
        return ('None',), i+1
    if t == '(':
        items = []
        i += 1
        while tokens[i] != ')':
            v, i = parse(tokens, i)
            items.append(v)
            if tokens[i] == ',':
                i += 1
        return ('tuple', items), i+1
    if t in ('[', 'list!'):
        if t == 'list!':
            i += 1
        assert tokens[i] == '['
        items = []
        i += 1
        while tokens[i] != ']':
            v, i = parse(tokens, i)
            items.append(v)
            if tokens[i] == ',':
                i += 1
        return ('list' if t == 'list!' else 'array', items), i+1
    return ('num', t), i+1

def render(v):
    k = v[0]
    if k == 'num':
        return v[1]
    if k == 'tuple':
        return '(' + ', '.join(render(x) for x in v[1]) + ')'
    if k == 'array':
        return '[' + ', '.join(render(x) for x in v[1]) + ']'
    if k == 'list':
        return 'list![' + ', '.join(render(x) for x in v[1]) + ']'
    if k in ('Left', 'Right', 'Some'):
        return k + '(' + render(v[1]) + ')'
    if k == 'None':
        return 'None'
    raise ValueError(k)

def main():
    src, dst = sys.argv[1], sys.argv[2]
    list_bound = 256
    if '--list-bound' in sys.argv:
        list_bound = int(sys.argv[sys.argv.index('--list-bound') + 1])
    w = json.load(open(src))
    proof = w['PROOF']['value']
    tree, _ = parse(tokenize(proof))
    assert tree[0] == 'tuple' and len(tree[1]) == 4
    message, pk, sig, root_part = tree[1]
    out = {}
    out['MESSAGE'] = {'type': 'u256', 'value': render(message)}
    out['PK'] = {'type': '(u128, u128)', 'value': render(pk)}
    out['ROOT_PART'] = {'type': 'u128', 'value': render(root_part)}
    kind = sig[0]
    if kind == 'Left':
        wots, path, key_idx = sig[1][1]
        r, counter, elems = wots[1]
        out['IS_STATEFUL'] = {'type': 'bool', 'value': 'true'}
        out['R'] = {'type': 'u256', 'value': render(r)}
        out['COUNTER'] = {'type': 'u32', 'value': render(counter)}
        out['SIG'] = {'type': '[u128; 64]', 'value': render(elems)}
        out['PATH'] = {'type': f'List<u128, {list_bound}>', 'value': render(path)}
        assert path[0] == 'list' and len(path[1]) >= 1
        out['PATH0'] = {'type': 'u128', 'value': render(path[1][0])}
        out['PATH_REST'] = {'type': f'List<u128, {list_bound}>', 'value': 'list![' + ', '.join(render(x) for x in path[1][1:]) + ']'}
        out['KEY_IDX'] = {'type': 'u32', 'value': render(key_idx)}
        out['HEAD'] = {'type': '((u128, u128), u32, u256, u256, u32)', 'value': '(' + ', '.join([render(pk), render(key_idx), render(message), render(r), render(counter)]) + ')'}
        # dummies for the stateless branch (pruned away)
        out['SPHINCS'] = {'type': '((u256, ([(u128, [u128; 22]); 4], [(u128, [u128; 22]); 1])), [((u256, u32, [u128; 64]), [u128; 12]); 2])',
                          'value': '((0, ([' + ', '.join(['(0, [' + ', '.join(['0']*22) + '])']*4) + '], [(0, [' + ', '.join(['0']*22) + '])])), [' +
                                   ', '.join(['((0, 0, [' + ', '.join(['0']*64) + ']), [' + ', '.join(['0']*12) + '])']*2) + '])'}
    else:
        out['IS_STATEFUL'] = {'type': 'bool', 'value': 'false'}
        out['SPHINCS'] = {'type': '((u256, ([(u128, [u128; 22]); 4], [(u128, [u128; 22]); 1])), [((u256, u32, [u128; 64]), [u128; 12]); 2])',
                          'value': render(sig[1])}
        fors_sig, ht_sig = sig[1][1]
        r_sl, parts = fors_sig[1]
        parts4, parts1 = parts[1]
        allparts = parts4[1] + parts1[1]
        out['HEAD_SL'] = {'type': '((u128, u128), u256, u256)', 'value': '(' + render(pk) + ', ' + render(message) + ', ' + render(r_sl) + ')'}
        out['FORS'] = {'type': '[(u128, [u128; 22]); 5]', 'value': '[' + ', '.join(render(p) for p in allparts) + ']'}
        for li, layer in enumerate(ht_sig[1]):
            wots, path = layer[1]
            _r, counter, elems = wots[1]
            out[f'X{li}_COUNTER'] = {'type': 'u32', 'value': render(counter)}
            out[f'X{li}_SIG'] = {'type': '[u128; 64]', 'value': render(elems)}
            out[f'X{li}_PATH'] = {'type': '[u128; 12]', 'value': render(path)}
        out['R'] = {'type': 'u256', 'value': '0'}
        out['COUNTER'] = {'type': 'u32', 'value': '0'}
        out['SIG'] = {'type': '[u128; 64]', 'value': '[' + ', '.join(['0']*64) + ']'}
        out['PATH'] = {'type': f'List<u128, {list_bound}>', 'value': 'list![]'}
        out['PATH0'] = {'type': 'u128', 'value': '0'}
        out['PATH_REST'] = {'type': f'List<u128, {list_bound}>', 'value': 'list![]'}
        out['KEY_IDX'] = {'type': 'u32', 'value': '0'}
        out['HEAD'] = {'type': '((u128, u128), u32, u256, u256, u32)', 'value': '(' + render(pk) + ', 0, ' + render(message) + ', 0, 0)'}
    json.dump(out, open(dst, 'w'), indent=1)
    print(f"wrote {dst}: kind={kind}")

main()
