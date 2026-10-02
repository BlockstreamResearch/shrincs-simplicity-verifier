#!/usr/bin/env python3
"""Generate the SHRINCS-L stateless verifier (FORS + two XMSS layers) as a hand-laid-out Simplicity DAG
(rust-simplicity human-readable encoding).

Usage: gen_stateless_dag.py <out.simpl> [--sum=4|32] [--g2] [--lean-constants]

  --sum=4        checksum of the WOTS digits accumulated per group of 4 digits (byte SWAR; default, smaller program)
  --sum=32       per 32 digits (64-bit SWAR): about -130k mWU for +85 bytes; better when the spend is CPU-budget bound
  --g2           two-tier WOTS fold (pairs of chains, then groups of four): -40 bytes, +130k mWU
  --lean-constants  assemble the SHA padding block from small words (-64 bytes, +1.3M mWU; only for reference)

Hash layouts (ref_verify_sl.py is the executable specification):
  tw(seed, ADRS, m) = SHA256(seed || 0^48 || ADRS || m)[:16]; ms = SHA-256 state after the block seed || 0^48.
  ADRS = layer(4) || tree(12) || typ(4) || w1 || w2 || w3, handled as (hi128, (mid64, lo64)) = (layer||tree, ((typ,w1),(w2,w3))).
  digest = SHA256(ADRS14 || r || seed || root || message): five 22-bit FORS leaf indices (a sixth must be zero) and a
  24-bit hypertree index; FORS leaf = tw(ADRS6(tree_no, 0, idx), sk); FORS/XMSS node = tw(ADRS7|12(height, idx >> height),
  left || right); FORS pk = tw(ADRS8, r0..r4); XMSS layer: digits = SHA256(ADRS13 || seed || message || counter)[:16],
  WOTS chains with ADRS10, leaf = tw(ADRS11, pk0..pk63), 12 path nodes; final = tw(ADRS16, uxmss_root || sphincs_root).

Design: the WOTS fold and the chain are those of the stateful program (Rest also carries the 128-bit layer||tree
prefix; the three chain steps are nested expressions over one environment); one shared `path_step` node serves the
110 FORS and 24 XMSS auth-path nodes; the FORS trees and the two XMSS layers are each one shared node applied
repeatedly; the auth-path elements carry their side as a sum tag (Left = the node in hand is the left child), which
the `case` dispatches on directly, and which the ADRS (height, index >> height) chain binds.

Witness:
  w_head    = ((seed, root), (message, r))
  w_fors0..4 = (sk, (A16, (A4, A2)))            A_n = n tagged nodes of type 2^128 + 2^128, in order
  w_x0, w_x1 = (counter, (sig: 2^8192, (A8, A4)))
  w_slroot  = uXMSS root (2^128)
"""
import sys

# ---------- DSL ----------
def P(path):
    assert path.endswith('H')
    e = 'iden'
    for c in reversed(path[:-1]):
        e = ('take ' if c == 'O' else 'drop ') + '(' + e + ')'
    return e

def comp(s, t): return f'comp ({s}) ({t})'
def pair(s, t): return f'pair ({s}) ({t})'
def case(s, t): return f'case ({s}) ({t})'
def take(s): return f'take ({s})'
def drop(s): return f'drop ({s})'
def jet(name): return f'jet_{name}'
def J(name, arg): return comp(arg, jet(name))

defs = []
def define(name, expr, ty=None):
    defs.append((name, expr, ty))
    return name

def T(bits):
    if bits <= 512:
        return f'2^{bits}'
    h = T(bits // 2)
    return f'({h} * {h})'

LEAN = '--lean-constants' in sys.argv
USE_G2 = '--g2' in sys.argv
SUM_LEVEL = 4
for a in sys.argv[2:]:
    if a.startswith('--sum='): SUM_LEVEL = int(a.split('=')[1])      # digit-sum granularity: 4 (byte SWAR per group) or 32 (64-bit SWAR)

# ---------- constants ----------
def word(bits, v):
    return f'comp unit (const 0x{v:0{bits // 4}x})'

ZERO_WORDS = {32}
def zero(bits):
    if bits in ZERO_WORDS:
        return word(bits, 0)
    h = zero(bits // 2)
    return pair(h, h)

def c4(v): return word(4, v)
def c8(v): return word(8, v)
def c32(v): return word(32, v)
def c64(v): return word(64, v)
def c128(v): return word(128, v)
Z32, Z64, Z128, Z256 = zero(32), zero(64), zero(128), zero(256)

def typ64(t):
    """(typ, 0) as the middle 64 bits of an ADRS."""
    return pair(c32(t), Z32)
def m64(v):
    """64-bit mask with only the low 32 bits set"""
    return pair(Z32, c32(v))

PAD_HI = pair(pair(c32(0x80000000), Z32), Z64)
def len_lo(bits): return pair(Z64, pair(Z32, c32(bits)))
def tail(bits): return pair(pair(c32(0x80000000), Z32), pair(Z32, c32(bits)))
TAILLEAF = pair(PAD_HI, len_lo(8960))
TAIL1408 = tail(1408)
if LEAN:
    PAD512 = pair(pair(PAD_HI, Z128), pair(Z128, len_lo(1024)))
    TAIL896 = tail(896)
else:
    PAD512 = word(512, (0x80 << 504) | 1024)                 # padding block of a 128-byte message (hot: every path node)
    TAIL896 = c128((0x80 << 120) | 896)                      # hot: every chain step

IV = comp('unit', jet('sha_256_iv'))
define('sha_take', comp(jet('sha_256_block'), take('iden')))       # 2^256 x 2^512 -> 2^128

def SHR64(n, a): return J('right_shift_64', pair(c8(n), a))
def SHL64(n, a): return J('left_shift_64', pair(c8(n), a))
def AND64(a, b): return J('and_64', pair(a, b))
def OR64(a, b): return J('or_64', pair(a, b))
def SHR32(n, a): return J('right_shift_32', pair(c8(n), a))
def AND32(a, b): return J('and_32', pair(a, b))
def INC32(a): return comp(J('increment_32', a), drop('iden'))
def or32(a, n): return J('or_32', pair(a, c32(n)))
def add32(a, n): return comp(J('add_32', pair(a, c32(n))), drop('iden'))

# ---------- witnesses ----------
TE = '(2^128 + 2^128)'
A = {1: TE}
for n in (2, 4, 8, 16):
    A[n] = f'({A[n // 2]} * {A[n // 2]})'
P22 = f'({A[16]} * ({A[4]} * {A[2]}))'
TREE = f'(2^128 * {P22})'
W5 = f'((({TREE} * {TREE}) * ({TREE} * {TREE})) * {TREE})'
P12 = f'({A[8]} * {A[4]})'
WX = f'(2^32 * ({T(8192)} * {P12}))'
define('w_head', 'witness', '_ -> (2^128 * 2^128) * (2^256 * 2^256)')
for t in range(5):
    define(f'w_fors{t}', 'witness', f'_ -> {TREE}')
define('w_x0', 'witness', f'_ -> {WX}')
define('w_x1', 'witness', f'_ -> {WX}')
define('w_slroot', 'witness', '_ -> 2^128')

# ---------- 1. digest, midstate, FORS state ----------
# E1 = ((seed, root), (message, r))
SEED, ROOT, MSG, R_ = P('OOH'), P('OIH'), P('IOH'), P('IIH')
adrs14 = pair(Z128, pair(typ64(14), Z64))
define('digest_e1', comp(pair(J('sha_256_block', pair(J('sha_256_block', pair(IV, pair(adrs14, R_))), pair(pair(SEED, ROOT), MSG))), PAD512), jet('sha_256_block')))
# E1' = (D, E1): D = ((m0, m1), (m2, m3)) as 64-bit words
M0, M1, M2 = P('OOOH'), P('OOIH'), P('OIOH')
SEED1, ROOT1 = P('IOOH'), P('IOIH')
def LOW32(x): return comp(x, drop('iden'))
i0 = LOW32(SHR64(42, M0))
i1 = LOW32(AND64(SHR64(20, M0), m64(0x3FFFFF)))
i2 = LOW32(OR64(SHL64(2, AND64(M0, m64(0xFFFFF))), SHR64(62, M1)))
i3 = LOW32(AND64(SHR64(40, M1), m64(0x3FFFFF)))
i4 = LOW32(AND64(SHR64(18, M1), m64(0x3FFFFF)))
check_i5 = J('verify', J('eq_64', pair(OR64(AND64(M1, m64(0x3FFFF)), SHR64(60, M2)), Z64)))
idx24 = AND32(SHR32(4, comp(M2, take('iden'))), c32(0xFFFFFF))
a128 = pair(Z64, pair(Z32, idx24))
ms_e1 = J('sha_256_block', pair(IV, pair(pair(SEED1, Z128), Z256)))
r5zero = pair(SEED1, pair(SEED1, pair(SEED1, pair(SEED1, SEED1))))   # placeholders, rotated out before use
i5 = pair(i0, pair(i1, pair(i2, pair(i3, i4))))
# F = (R5, (I5, (tree_no, (A128, K)))), K = (seed, (ms, root))
f0 = pair(r5zero, pair(i5, pair(Z32, pair(a128, pair(SEED1, pair(ms_e1, ROOT1))))))
define('build_f0', comp(pair(check_i5, 'iden'), drop(f0)))

# ---------- 2. auth-path step, shared by FORS and XMSS ----------
# PS = (C, (node, (height, parent))), C = (adrs_hi128, (adrs_mid64, ms)); element = Left(el) | Right(el)
# branch env (el, PS): el = OH, C = IOH, hi = IOOH, mid = IOIOH, ms = IOIIH, node = IIOH, hp = IIIH, height = IIIOH, parent = IIIIH
EL, C_, HI, MID, MS_, NODE, HP, HEIGHT, PARENT = P('OH'), P('IOH'), P('IOOH'), P('IOIOH'), P('IOIIH'), P('IIOH'), P('IIIH'), P('IIIOH'), P('IIIIH')
adrs_hp = pair(HI, pair(MID, HP))
hp_next = pair(INC32(HEIGHT), SHR32(1, PARENT))
def step(lr):
    h = comp(pair(J('sha_256_block', pair(MS_, pair(adrs_hp, lr))), PAD512), 'sha_take')
    return pair(C_, pair(h, hp_next))
define('path_step', case(step(pair(NODE, EL)), step(pair(EL, NODE))))
define('arr1', 'path_step')
for n in (2, 4, 8, 16):
    half = f'arr{n // 2}'
    define(f'arr{n}', comp(pair(P('OIH'), comp(pair(P('OOH'), P('IH')), half)), half))
# (P22, PS) -> PS and (P12, PS) -> PS
define('fold22', comp(pair(P('OIH'), comp(pair(P('OOH'), P('IH')), 'arr16')), comp(pair(P('OIH'), comp(pair(P('OOH'), P('IH')), 'arr4')), 'arr2')))
define('fold12', comp(pair(P('OIH'), comp(pair(P('OOH'), P('IH')), 'arr8')), 'arr4'))

# ---------- 3. FORS tree: ((sk, P22), F) -> F ----------
SK, PATH22 = P('OOH'), P('OIH')
R1, R2, R3, R4 = P('IOIOH'), P('IOIIOH'), P('IOIIIOH'), P('IOIIIIH')
I0, I1, I2, I3, I4 = P('IIOOH'), P('IIOIOH'), P('IIOIIOH'), P('IIOIIIOH'), P('IIOIIIIH')
TN, A128F, KF, MSF = P('IIIOH'), P('IIIIOH'), P('IIIIIH'), P('IIIIIIOH')
adrs6 = pair(A128F, pair(pair(c32(6), TN), pair(Z32, I0)))
leaf_f = comp(pair(MSF, pair(adrs6, pair(SK, TAIL896))), 'sha_take')
c7 = pair(A128F, pair(pair(c32(7), TN), MSF))
ps0_f = pair(c7, pair(leaf_f, pair(c32(1), SHR32(1, I0))))
root_f = comp(comp(pair(PATH22, ps0_f), 'fold22'), P('IOH'))
r5_next = pair(R1, pair(R2, pair(R3, pair(R4, root_f))))
i5_next = pair(I1, pair(I2, pair(I3, pair(I4, I0))))
define('fors_tree', pair(r5_next, pair(i5_next, pair(INC32(TN), pair(A128F, KF)))))
# the five trees one after the other, each read from its own witness node (no copying of the whole FORS witness)
expr = comp(pair('w_fors4', 'iden'), 'fors_tree')
for t in (3, 2, 1, 0):
    expr = comp(pair(f'w_fors{t}', 'iden'), comp('fors_tree', expr))
define('fors_all', expr)

# ---------- 4. FORS pk and the first XMSS context: F -> CTX ----------
# CTX = (message, (key_idx, (pre128, (idx, K))))
R0F, R1F, R2F, R3F, R4F = P('OOH'), P('OIOH'), P('OIIOH'), P('OIIIOH'), P('OIIIIH')
A128G, IDX24G, KG, MSG_ = P('IIIOH'), P('IIIOIIH'), P('IIIIH'), P('IIIIIOH')
adrs8 = pair(A128G, pair(typ64(8), Z64))
fors_pk = comp(pair(J('sha_256_block', pair(MSG_, pair(adrs8, pair(R0F, R1F)))), pair(pair(R2F, R3F), pair(R4F, TAIL1408))), 'sha_take')
define('fors_finish', pair(fors_pk, pair(AND32(IDX24G, c32(0xFFF)), pair(pair(Z64, pair(Z32, SHR32(12, IDX24G))), pair(SHR32(12, IDX24G), KG)))))

# ---------- 5. WOTS chain and fold (Rest = (idx, (ms, (pre128, pre64)))) ----------
# X = (s, Rest). The steps are nested expressions over the same environment: the inner step's 256-bit SHA state feeds
# the outer block through `comp (inner) (pair (take iden) TAIL)`, so no environment is rebuilt between steps and the
# result is truncated to 128 bits once per chain.
S_, IDX, MS, PRE128, PRE64 = P('OH'), P('IOH'), P('IIOH'), P('IIIOH'), P('IIIIH')
def adrs_k(k): return pair(PRE128, pair(PRE64, pair(IDX, c32(k))))
first = pair(S_, TAIL896)                                            # (s, tail) : X -> 2^256
def nest(k, ypart): return J('sha_256_block', pair(MS, pair(adrs_k(k), ypart)))
def over(inner): return comp(inner, pair(take('iden'), TAIL896))     # 256-bit state -> (y, tail)
n0 = nest(0, first)
n01 = nest(1, over(n0))
n012 = nest(2, over(n01))
n1 = nest(1, first)
n12 = nest(2, over(n1))
n2 = nest(2, first)
define('f012', comp(n012, take('iden')))
define('f12', comp(n12, take('iden')))
define('f2', comp(n2, take('iden')))
define('chain', case(drop(case(drop('f012'), drop('f12'))), drop(case(drop('f2'), drop(take('iden'))))))

def AND8(a, b): return J('and_8', pair(a, b))
def SHR8(n, a): return J('right_shift_8', pair(c4(n), a))
def ADD8(a, b): return comp(J('add_8', pair(a, b)), drop('iden'))
def AND64b(a, b): return J('and_64', pair(a, b))
def SHR64b(n, a): return J('right_shift_64', pair(c8(n), a))
def ADD64(a, b): return comp(J('add_64', pair(a, b)), drop('iden'))
# sum of 32 two-bit digits packed in a 64-bit word (<= 96): 2-bit fields -> nibbles -> bytes -> horizontal sum, low byte
y64 = ADD64(AND64b('iden', c64(0x3333333333333333)), AND64b(SHR64b(2, 'iden'), c64(0x3333333333333333)))
z64 = comp(pair(y64, 'unit'), ADD64(AND64b(P('OH'), c64(0x0F0F0F0F0F0F0F0F)), AND64b(SHR64b(4, P('OH')), c64(0x0F0F0F0F0F0F0F0F))))
define('dsum64', comp(SHR64b(56, comp(J('multiply_64', pair(z64, c64(0x0101010101010101))), drop('iden'))), P('IIIH')), '2^64 -> 2^8')
def AND8(a, b): return J('and_8', pair(a, b))
def SHR8(n, a): return J('right_shift_8', pair(c4(n), a))
y8 = ADD8(AND8('iden', c8(0x33)), AND8(SHR8(2, 'iden'), c8(0x33)))
define('dsum8', SHR8(4, comp(J('multiply_8', pair(y8, c8(0x11))), drop('iden'))), '2^8 -> 2^8')

# Sigma = (Rest, ((st, pend), sum)); level env = ((S, D), Sigma)
if USE_G2:
    c0 = comp(pair(P('OIOOH'), pair(P('OIOIH'), pair(P('OOOH'), P('IH')))), 'chain')
    c1 = comp(pair(P('OIIOH'), pair(P('OIIIH'), pair(P('OOIH'), pair(or32(P('IOH'), 1), P('IIH'))))), 'chain')
    define('g2', pair(c0, c1))
    g0 = comp(pair(pair(P('OOOH'), P('OIOH')), P('IOH')), 'g2')
    g1 = comp(pair(pair(P('OOIH'), P('OIIH')), pair(or32(P('IOOH'), 2), P('IOIH'))), 'g2')
    pk01, pk23 = g0, g1
else:
    # four direct chain calls per group: ((S4, D4), Sigma); s_j = OO.., d_j bits from D4 = ((d0,d1),(d2,d3))
    def call(j):
        s = P('OO' + ['OO', 'OI', 'IO', 'II'][j] + 'H')
        hi = P('OI' + ['OO', 'OI', 'IO', 'II'][j] + 'OH')
        lo = P('OI' + ['OO', 'OI', 'IO', 'II'][j] + 'IH')
        rest = P('IOH') if j == 0 else pair(or32(P('IOOH'), j), P('IOIH'))
        return comp(pair(hi, pair(lo, pair(s, rest))), 'chain')
    pk01 = pair(call(0), call(1))
    pk23 = pair(call(2), call(3))
st1 = J('sha_256_block', pair(P('IIOOH'), pair(P('IIOIH'), pk01)))
sum4 = ADD8(P('IIIH'), comp(P('OIH'), 'dsum8')) if SUM_LEVEL == 4 else P('IIIH')
define('h4', pair(pair(add32(P('IOOH'), 4), P('IOIH')), pair(pair(st1, pk23), sum4)))
prev = 'h4'
for n in [8, 16, 32, 64]:
    left = comp(pair(pair(P('OOOH'), P('OIOH')), P('IH')), prev)
    whole = comp(pair(pair(P('OOIH'), P('OIIH')), left), prev)
    if n == 32 and SUM_LEVEL == 32:
        # add the digit sum of these 32 digits to Sigma.sum: env ((S32, D32), Sigma) -> Sigma'
        whole = comp(pair(comp(P('OIH'), 'dsum64'), whole), pair(P('IOH'), pair(P('IIOH'), ADD8(P('IIIH'), P('OH')))))
    prev = define(f'h{n}', whole)

# ---------- 6. XMSS layer: ((counter, (sig, P12)), CTX) -> CTX ----------
COUNTER, SIG, PATH12 = P('OOH'), P('OIOH'), P('OIIH')
MESSAGE, KEYIDX, PRE128X, IDXX, KX, SEEDX, MSX, LAYER = P('IOH'), P('IIOH'), P('IIIOH'), P('IIIIOH'), P('IIIIIH'), P('IIIIIOH'), P('IIIIIIOH'), P('IIIOOOH')
adrs13 = pair(PRE128X, pair(pair(c32(13), KEYIDX), Z64))
blk2 = pair(pair(pair(pair(COUNTER, c32(0x80000000)), Z64), Z128), pair(Z128, len_lo(544)))
digits = comp(pair(J('sha_256_block', pair(IV, pair(adrs13, pair(SEEDX, MESSAGE)))), blk2), 'sha_take')
pre64x = pair(c32(10), KEYIDX)
adrs11 = pair(PRE128X, pair(pair(c32(11), KEYIDX), Z64))
sigma0 = pair(pair(Z32, pair(MSX, pair(PRE128X, pre64x))), pair(pair(MSX, adrs11), c8(0)))
foldin = pair(pair(SIG, digits), sigma0)
check_sum = J('verify', J('eq_8', pair(P('IIH'), c8(140))))
final_block = comp(pair(P('IOOH'), pair(P('IOIH'), TAILLEAF)), 'sha_take')
leaf_x = comp(foldin, comp('h64', comp(pair(check_sum, 'iden'), drop(final_block))))
c12 = pair(PRE128X, pair(typ64(12), MSX))
ps0_x = pair(c12, pair(leaf_x, pair(c32(1), SHR32(1, KEYIDX))))
root_x = comp(comp(pair(PATH12, ps0_x), 'fold12'), P('IOH'))
pre128_next = pair(pair(INC32(LAYER), Z32), pair(Z32, SHR32(12, IDXX)))
define('xmss_layer', pair(root_x, pair(IDXX, pair(pre128_next, pair(SHR32(12, IDXX), KX)))))

# ---------- 7. final root check: CTX -> 1 ----------
ROOTX, KC, MSC, PKROOT = P('OH'), P('IIIIH'), P('IIIIIOH'), P('IIIIIIH')
adrs16 = pair(Z128, pair(typ64(16), Z64))
final = comp(pair(J('sha_256_block', pair(MSC, pair(adrs16, pair('w_slroot', ROOTX)))), PAD512), 'sha_take')
define('final_check', J('verify', J('eq_256', pair(pair(ROOTX, final), pair(ROOTX, PKROOT)))))

define('main', comp('w_head', comp(pair('digest_e1', 'iden'), comp('build_f0', comp('fors_all', comp('fors_finish',
       comp(pair('w_x0', 'iden'), comp('xmss_layer', comp(pair('w_x1', 'iden'), comp('xmss_layer', 'final_check'))))))))))

out = sys.argv[1]
with open(out, 'w') as f:
    for name, expr, ty in defs:
        f.write(f'{name} := {expr} : {ty}\n' if ty else f'{name} := {expr}\n')
print(f'wrote {out} ({len(defs)} definitions)')
