#!/usr/bin/env python3
"""Compute transaction sizes for every key index under both tapleaf layouts; write results/full_table.{json,csv}.

Layout 1 (3 tapleaves): general program (key indices 1..206) at depth 1; the index-207 program and the stateless
  program at depth 2.
Layout 2 (208 tapleaves, balanced): one program per key index at depth 8 (cold constants for short auth paths, hot
  padding constants and nested chain steps for long ones, whichever gives the smaller transaction); the stateless
  program at depth 8.

Paths: harness binary ../tools/harness/target/release/hand (HAND_BIN), witness specs ./witnesses_all and
./witnesses_sl (WITDIR / WITDIR_SL, made by make_witness.py / make_witness_sl.py), previous verifier's curve
../vectors/curve.json and comparison ../vectors/comparison.json. Generated programs go to ./programs_all.
"""
import csv, json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
from txsize import model
H = os.environ.get('HAND_BIN', os.path.join(HERE, '..', 'tools', 'harness', 'target', 'release', 'hand'))
WITDIR = os.environ.get('WITDIR', os.path.join(HERE, 'witnesses_all'))
WITDIR_SL = os.environ.get('WITDIR_SL', os.path.join(HERE, 'witnesses_sl'))
GEN = os.path.join(HERE, 'gen_stateful_dag.py')
GEN_SL = os.path.join(HERE, 'gen_stateless_dag.py')
PROGS = os.path.join(HERE, 'programs_all')
os.makedirs(PROGS, exist_ok=True)
os.makedirs(os.path.join(HERE, 'results'), exist_ok=True)

def gen(path, *flags):
    subprocess.run(['python3', GEN, path] + list(flags), check=True, capture_output=True)

def run(prog, wit):
    out = subprocess.run([H, prog, wit], capture_output=True, text=True).stdout
    r = json.loads(out)
    assert r['ok'], (prog, wit, r)
    return r

prev = {row[0]: row[1] for row in json.load(open(os.path.join(HERE, '..', 'vectors', 'curve.json')))}
general = os.path.join(PROGS, 'general.simpl'); gen(general, '--no-last')
q207 = os.path.join(PROGS, 'stateful_q207.simpl'); gen(q207, '--fixed-q=207', '--hot-pad', '--nested-chain')
rows = []
for q in range(1, 208):
    wit = os.path.join(WITDIR, f'stateful_q{q}.hand.json')
    r1 = run(general if q <= 206 else q207, wit)
    m1 = model(r1['cost'], r1['program_bytes'], r1['witness_bytes'], 32 if q <= 206 else 64)
    best = None
    for flags, tag in (((), 'cold'), (('--hot-pad',), 'hot-pad'), (('--hot-pad', '--nested-chain'), 'hot-pad+nested')):
        prog = os.path.join(PROGS, f'stateful_q{q}{"_" + tag.replace("+", "_").replace("-", "") if flags else ""}.simpl')
        gen(prog, f'--fixed-q={q}', *flags)
        r = run(prog, wit)
        m = model(r['cost'], r['program_bytes'], r['witness_bytes'], 256)
        if best is None or m['tx_vsize_vb'] < best[1]['tx_vsize_vb']:
            best = (r, m, tag)
    r2, m2, tag2 = best
    rows.append({'q': q, 'simplicityhl_vsize': prev.get(q),
                 'layout1': {'program': 'general' if q <= 206 else 'q207', 'cost': r1['cost'], 'program_bytes': r1['program_bytes'],
                             'witness_bytes': r1['witness_bytes'], 'control_block': 65 if q <= 206 else 97, **m1},
                 'layout2': {'program': f'q{q} ({tag2})', 'cost': r2['cost'], 'program_bytes': r2['program_bytes'],
                             'witness_bytes': r2['witness_bytes'], 'control_block': 289, **m2}})
    if q in (1, 2, 3, 5, 10, 20, 50, 100, 150, 206, 207):
        print(f"q={q:3d}  simplicityhl {prev.get(q)}  layout1 {m1['tx_vsize_vb']:5d} vB (prog {r1['program_bytes']}, pad {m1['annex_padding_bytes']})"
              f"  layout2 {m2['tx_vsize_vb']:5d} vB (prog {r2['program_bytes']} {tag2}, pad {m2['annex_padding_bytes']})")
# stateless leaf: depth 2 in layout 1, depth 8 in layout 2; the checksum granularity is chosen per layout
prev_sl = [r for r in json.load(open(os.path.join(HERE, '..', 'vectors', 'comparison.json'))) if r['version'] == 'this work' and r['vector'] == 'stateless']
sl_prev = prev_sl[0]['tx_vsize_vb'] if prev_sl else None
sl_rows = {}
for layout, depth in (('layout1', 2), ('layout2', 8)):
    best = None
    for flags, tag in (((), 'sum4'), (('--sum=32',), 'sum32')):
        prog = os.path.join(PROGS, f'stateless_{tag}.simpl')
        subprocess.run(['python3', GEN_SL, prog] + list(flags), check=True, capture_output=True)
        r = run(prog, os.path.join(WITDIR_SL, 'stateless_0.hand.json'))
        m = model(r['cost'], r['program_bytes'], r['witness_bytes'], 32 * depth)
        if best is None or m['tx_vsize_vb'] < best[1]['tx_vsize_vb']:
            best = (r, m, tag)
    r, m, tag = best
    sl_rows[layout] = {'program': f'stateless ({tag})', 'cost': r['cost'], 'program_bytes': r['program_bytes'], 'witness_bytes': r['witness_bytes'], 'control_block': 33 + 32 * depth, **m}
    print(f"stateless {layout}: {m['tx_vsize_vb']} vB (prog {r['program_bytes']} {tag}, pad {m['annex_padding_bytes']})" + (f"  simplicityhl: {sl_prev}" if sl_prev else ''))
rows.append({'q': 'stateless', 'simplicityhl_vsize': sl_prev, 'layout1': sl_rows['layout1'], 'layout2': sl_rows['layout2']})
json.dump(rows, open(os.path.join(HERE, 'results', 'full_table.json'), 'w'), indent=1)
with open(os.path.join(HERE, 'results', 'full_table.csv'), 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['q', 'simplicityhl_vsize', 'layout1_program', 'layout1_cost', 'layout1_program_bytes', 'layout1_witness_bytes', 'layout1_padding', 'layout1_vsize',
                'layout2_program', 'layout2_cost', 'layout2_program_bytes', 'layout2_witness_bytes', 'layout2_padding', 'layout2_vsize'])
    for r in rows:
        a, b = r['layout1'], r['layout2']
        w.writerow([r['q'], r['simplicityhl_vsize'], a['program'], a['cost'], a['program_bytes'], a['witness_bytes'], a['annex_padding_bytes'], a['tx_vsize_vb'],
                    b['program'], b['cost'], b['program_bytes'], b['witness_bytes'], b['annex_padding_bytes'], b['tx_vsize_vb']])
srows = [r for r in rows if r['q'] != 'stateless']
ap = sum(prev.values()) / len(prev)
a1 = sum(r['layout1']['tx_vsize_vb'] for r in srows) / len(srows)
a2 = sum(r['layout2']['tx_vsize_vb'] for r in srows) / len(srows)
print(f'average over all 207 key indices: simplicityhl {ap:.1f} vB, layout1 {a1:.1f} vB ({100*(1-a1/ap):.1f}% smaller), layout2 {a2:.1f} vB ({100*(1-a2/ap):.1f}% smaller)')
