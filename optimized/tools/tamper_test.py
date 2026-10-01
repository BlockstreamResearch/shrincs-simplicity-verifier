#!/usr/bin/env python3
"""Tamper with each component of an optimized-format witness and check that the verifier rejects it.
Usage: tamper_test.py <program.simf> <witness.opt.wit> <check-binary>
"""
import json, re, subprocess, sys, copy

prog, wit_path, check = sys.argv[1:4]
w = json.load(open(wit_path))
stateful = w['IS_STATEFUL']['value'] == 'true'

def nums(s):
    # positions of decimal numbers in a value string
    return [(m.start(), m.end()) for m in re.finditer(r'\d+', s)]

def flip_num(s, k, delta=1):
    """Modify the k-th number in value string s by +delta (keeping it non-negative)."""
    spans = nums(s)
    a, b = spans[k]
    v = int(s[a:b]) + delta
    if v < 0:
        v = 1
    return s[:a] + str(v) + s[b:]

cases = []
if stateful:
    # HEAD = ((seed, root), key_idx, message, r, counter): numbers 0..5
    cases += [('HEAD.pk_seed', 'HEAD', 0), ('HEAD.pk_root', 'HEAD', 1), ('HEAD.key_idx', 'HEAD', 2), ('HEAD.message', 'HEAD', 3), ('HEAD.r', 'HEAD', 4), ('HEAD.counter', 'HEAD', 5)]
    cases += [('SIG[0]', 'SIG', 0), ('SIG[63]', 'SIG', 63), ('PATH0', 'PATH0', 0), ('ROOT_PART', 'ROOT_PART', 0)]
    for k in ('PATH1', 'PATH2'):
        if k in w and nums(w[k]['value']):
            cases += [(k, k, 0)]
    if len(nums(w['PATH']['value'])) > 0:
        cases += [('PATH[last]', 'PATH', len(nums(w['PATH']['value'])) - 1)]
else:
    cases += [('HEAD_SL.pk_root', 'HEAD_SL', 1), ('HEAD_SL.message', 'HEAD_SL', 2), ('HEAD_SL.r', 'HEAD_SL', 3)]
    cases += [('FORS.sk[0]', 'FORS', 0), ('FORS.path[0][21]', 'FORS', 22), ('FORS.sk[4]', 'FORS', 4 * 23), ('FORS.path[4][0]', 'FORS', 4 * 23 + 1)]
    for i in (0, 1):
        cases += [(f'X{i}_COUNTER', f'X{i}_COUNTER', 0), (f'X{i}_SIG[5]', f'X{i}_SIG', 5), (f'X{i}_PATH[11]', f'X{i}_PATH', 11)]
    cases += [('ROOT_PART_SL', 'ROOT_PART_SL', 0)]

results = []
for name, key, k in cases:
    w2 = copy.deepcopy(w)
    w2[key]['value'] = flip_num(w2[key]['value'], k)
    tmp = wit_path + '.tamper.json'
    json.dump(w2, open(tmp, 'w'))
    out = subprocess.run([check, prog, tmp], capture_output=True, text=True).stdout.strip()
    try:
        r = json.loads(out)
    except Exception:
        r = {'ok': None, 'error': out[:120]}
    verdict = 'REJECTED' if r.get('ok') is False else ('ACCEPTED!!' if r.get('ok') else 'ERR')
    results.append((name, verdict, r.get('stage', ''), r.get('error', '')[:60]))
    print(f"{name:20s} {verdict:10s} {r.get('stage','')} {r.get('error','')[:60]}")
bad = [r for r in results if r[1] != 'REJECTED']
print(f"== {len(results)} tamper cases, {len(bad)} not rejected ==")
sys.exit(1 if bad else 0)
