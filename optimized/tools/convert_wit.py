#!/usr/bin/env python3
"""Convert the repo's single-value PROOF witness (examples/shrincs/*.wit, type SHRINCSSignProof)
into the split witness layout used by optimized/shrincs_opt.simf.

Usage: convert_wit.py <in.wit> <out.wit>

Output layout:
  IS_STATEFUL: bool
  stateful : HEAD = (pk, key_idx, message, r, counter), SIG = [u128; 64], PATH0 = u128 (first auth node),
             PATH1, PATH2 = Option<u128> (second and third auth node), PATH = List<u128, 256> (the rest), ROOT_PART = u128
  stateless: HEAD_SL = (pk, message, r), FORS = [(sk, [u128; 22]); 5], X{0,1}_COUNTER/_SIG/_PATH, ROOT_PART_SL = u128
The branch that is not taken gets zero-valued dummies; it is pruned away and nothing of it is encoded.
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

def arr(items):
    return '[' + ', '.join(items) + ']'

def zeros(n):
    return arr(['0'] * n)

def dummy_stateless():
    z22 = zeros(22)
    out = {}
    out['HEAD_SL'] = {'type': '((u128, u128), u256, u256)', 'value': '((0, 0), 0, 0)'}
    out['FORS'] = {'type': '[(u128, [u128; 22]); 5]', 'value': arr(['(0, ' + z22 + ')'] * 5)}
    for i in (0, 1):
        out[f'X{i}_COUNTER'] = {'type': 'u32', 'value': '0'}
        out[f'X{i}_SIG'] = {'type': '[u128; 64]', 'value': zeros(64)}
        out[f'X{i}_PATH'] = {'type': '[u128; 12]', 'value': zeros(12)}
    out['ROOT_PART_SL'] = {'type': 'u128', 'value': '0'}
    return out

def dummy_stateful():
    out = {}
    out['HEAD'] = {'type': '((u128, u128), u32, u256, u256, u32)', 'value': '((0, 0), 0, 0, 0, 0)'}
    out['SIG'] = {'type': '[u128; 64]', 'value': zeros(64)}
    out['PATH0'] = {'type': 'u128', 'value': '0'}
    out['PATH1'] = {'type': 'Option<u128>', 'value': 'None'}
    out['PATH2'] = {'type': 'Option<u128>', 'value': 'None'}
    out['PATH'] = {'type': 'List<u128, 256>', 'value': 'list![]'}
    out['ROOT_PART'] = {'type': 'u128', 'value': '0'}
    return out

def main():
    src, dst = sys.argv[1], sys.argv[2]
    w = json.load(open(src))
    tree, _ = parse(tokenize(w['PROOF']['value']))
    assert tree[0] == 'tuple' and len(tree[1]) == 4, 'expected (message, pk, Either<...>, root_part)'
    message, pk, sig, root_part = tree[1]
    out = {}
    if sig[0] == 'Left':
        wots, path, key_idx = sig[1][1]
        r, counter, elems = wots[1]
        assert path[0] == 'list' and len(path[1]) >= 1, 'the auth path must have at least one node'
        out['IS_STATEFUL'] = {'type': 'bool', 'value': 'true'}
        out['HEAD'] = {'type': '((u128, u128), u32, u256, u256, u32)',
                       'value': '(' + ', '.join([render(pk), render(key_idx), render(message), render(r), render(counter)]) + ')'}
        out['SIG'] = {'type': '[u128; 64]', 'value': render(elems)}
        nodes = [render(x) for x in path[1]]
        out['PATH0'] = {'type': 'u128', 'value': nodes[0]}
        out['PATH1'] = {'type': 'Option<u128>', 'value': 'Some(' + nodes[1] + ')' if len(nodes) > 1 else 'None'}
        out['PATH2'] = {'type': 'Option<u128>', 'value': 'Some(' + nodes[2] + ')' if len(nodes) > 2 else 'None'}
        out['PATH'] = {'type': 'List<u128, 256>', 'value': 'list![' + ', '.join(nodes[3:]) + ']'}
        out['ROOT_PART'] = {'type': 'u128', 'value': render(root_part)}
        out.update(dummy_stateless())
    elif sig[0] == 'Right':
        fors_sig, ht_sig = sig[1][1]
        r_sl, parts = fors_sig[1]
        parts4, parts1 = parts[1]
        allparts = parts4[1] + parts1[1]
        out['IS_STATEFUL'] = {'type': 'bool', 'value': 'false'}
        out.update(dummy_stateful())
        out['HEAD_SL'] = {'type': '((u128, u128), u256, u256)', 'value': '(' + render(pk) + ', ' + render(message) + ', ' + render(r_sl) + ')'}
        out['FORS'] = {'type': '[(u128, [u128; 22]); 5]', 'value': arr(render(p) for p in allparts)}
        for li, layer in enumerate(ht_sig[1]):
            wots, path = layer[1]
            _r, counter, elems = wots[1]
            out[f'X{li}_COUNTER'] = {'type': 'u32', 'value': render(counter)}
            out[f'X{li}_SIG'] = {'type': '[u128; 64]', 'value': render(elems)}
            out[f'X{li}_PATH'] = {'type': '[u128; 12]', 'value': render(path)}
        out['ROOT_PART_SL'] = {'type': 'u128', 'value': render(root_part)}
    else:
        raise ValueError('signature must be Left(uxmss) or Right(sphincs)')
    json.dump(out, open(dst, 'w'), indent=1)
    print(f"wrote {dst} ({'stateful' if sig[0] == 'Left' else 'stateless'})")

main()
