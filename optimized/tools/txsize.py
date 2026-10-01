#!/usr/bin/env python3
"""Transaction size model for a Simplicity (tapsimplicity, leaf 0xbe) spend on Liquid/Elements.

Budget rule (Elements src/script/interpreter.cpp): budget = serialized witness-stack bytes + 50 (WU);
the program's static cost bound (milli-WU) must be <= budget * 1000. If the natural stack is too small,
padding bytes are added in an annex element (rust-simplicity's Cost::get_padding does exactly this).

Witness stack: [simplicity witness, simplicity program, script (32-byte CMR), control block (33 bytes)] (+ annex).
Base tx (non-witness) for a 1-input, 1-output + fee-output explicit Liquid transaction: 173 bytes
  version 4 + flag 1 + vin count 1 + input 41 + vout count 1 + output (33 asset + 9 value + 1 nonce + 1 + 34 script)
  + fee output (33 + 9 + 1 + 1) + locktime 4.
Witness part also carries 7 bytes of empty issuance/pegin/range/surjection proof fields.
weight = 3 * base + (base + 7 + W); vsize = ceil(weight / 4).
"""
import json, math, sys

BASE_TX = 173
WITNESS_EXTRA = 7

def varint(n):
    return 1 if n < 253 else (3 if n <= 0xFFFF else 5)

def stack_bytes(elems):
    return 1 + sum(varint(len_) + len_ for len_ in elems)

def model(cost_mwu, program_bytes, witness_bytes, extra_control=0):
    elems = [witness_bytes, program_bytes, 32, 33 + extra_control]
    w0 = stack_bytes(elems)
    need = math.ceil(cost_mwu / 1000)           # WU of budget needed
    annex = 0
    if w0 + 50 < need:
        # annex element: varint(len) + len bytes, first byte 0x50
        annex = need - 50 - w0 - 1
        while w0 + varint(annex) + annex + 50 < need:
            annex += 1
    w = w0 + (varint(annex) + annex if annex else 0)
    weight = 3 * BASE_TX + (BASE_TX + WITNESS_EXTRA + w)
    return {
        'natural_stack_bytes': w0,
        'budget_needed_wu': need,
        'annex_padding_bytes': annex,
        'witness_stack_bytes': w,
        'tx_weight_wu': weight,
        'tx_vsize_vb': math.ceil(weight / 4),
        'witness_only_vb': round(w / 4, 1),
    }

if __name__ == '__main__':
    rows = json.load(open(sys.argv[1]))
    print(f"{'case':34s} {'cost mWU':>11s} {'prog B':>7s} {'wit B':>6s} {'stack':>6s} {'pad':>6s} {'weight':>7s} {'vsize':>6s}")
    for r in rows:
        m = model(r['cost'], r['program_bytes'], r['witness_bytes'], r.get('extra_control', 0))
        print(f"{r['name']:34s} {r['cost']:>11,d} {r['program_bytes']:>7d} {r['witness_bytes']:>6d} {m['natural_stack_bytes']:>6d} {m['annex_padding_bytes']:>6d} {m['tx_weight_wu']:>7d} {m['tx_vsize_vb']:>6d}")
