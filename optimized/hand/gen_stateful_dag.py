#!/usr/bin/env python3
"""Generate the SHRINCS-L stateful verifier as a hand-laid-out Simplicity DAG (rust-simplicity human-readable encoding).

Usage: gen_stateful_dag.py <out.simpl> [--fixed-q=N | --no-last] [--hot-pad] [--cost-bound] [--hot-zero=32|64|128]
                                        [--hot-tail=32|64|128] [--e4=A|B]

  default      general program: key_idx from the witness; auth path = path0 + Option(path1) + Option(path2) + List<..,256>
  --no-last    general program for key indices 1..206 only (index 207, the only right-child leaf, gets its own tapleaf),
               which removes the branch on the leaf position (one hidden CMR + a few nodes)
  --fixed-q=N  program specialised for key index N (meant to be its own tapleaf): key_idx is a constant, the auth-path
               length is fixed, no branches at all
  --hot-pad    build the SHA padding block of the path/root/message hashes from 128-bit words (-4.8k mWU per path node,
               +28 bytes): better for key indices above ~60, where the spend is CPU-budget bound
  --cost-bound use wide constant words everywhere (only for spends whose size is set by the CPU budget)
  --hot-zero / --hot-tail  width of the zero / padding-tail words used in the WOTS chain step (bigger = fewer cycles,
               more bytes); the defaults (128) are the right trade for every program we measured
  --e4         layout of the auth-path state (A: ((h, node), (root, ms)), B: (node, (h, (root, ms)))); the serialised
               size differs by a few bytes; the default picks the smaller one for each mode

Design (see README.md):
  * every tweaked hash is SHA256(seed || 0^48 || ADRS || m)[:16]; `ms` is the SHA-256 state after the first block
    (seed || 0^48), computed once; a chain step is one sha_256_block call (ADRS || y || padding fits one block);
    a path node is two (ADRS || left || right, then the padding block).
  * ADRS (32 bytes) = (Z128, ((typ, w1), (w2, w3))) with the layer/tree fields zero.
  * WOTS chain `chain : (hi, (lo, (y, Rest))) -> pk` dispatches on the two digit bits with nested `case` (no
    environment copies); the three step functions are shared nodes; the cost bound is the 3-step branch.
  * the 64 chains are folded with a halving fold; the state Sigma = ((st, pend), ((idx, (ms, pre64)), sum)) threads
    the streamed SHA-256 of the leaf (st = state, pend = half block waiting), the chain index and the digit sum
    (4 digits per group, SWAR on a byte) through the levels; the leaf and the checksum come out of the same fold.
  * environments are products built by `pair`, accessed by take/drop paths written as strings of O/I ending in H.
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

FIXED_Q = None
HOT_ZERO = 128
HOT_TAIL = 128
HOT_PAD = False
NO_LAST = False
COST_BOUND = False
for a in sys.argv[2:]:
    if a == '--no-last': NO_LAST = True
    if a == '--cost-bound': COST_BOUND = True; HOT_PAD = True
    if a.startswith('--fixed-q='): FIXED_Q = int(a.split('=')[1])
    if a.startswith('--hot-zero='): HOT_ZERO = int(a.split('=')[1])
    if a.startswith('--hot-tail='): HOT_TAIL = int(a.split('=')[1])
    if a == '--hot-pad': HOT_PAD = True

# ---------- constants ----------
def word(bits, v):
    return f'comp unit (const 0x{v:0{bits // 4}x})'

ZERO_WORDS = {32, 64, 128, 256} if COST_BOUND else {32, HOT_ZERO}
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

Z32, Z64, Z128 = zero(32), zero(64), zero(128)

def adrs(typ, w1, w2, w3):
    return pair(Z128, pair(pair(typ, w1), pair(w2, w3)))
def adrs_t(typ_val, w2):
    """ADRS with a constant (typ, w1 = 0) pair and w3 = 0; in cost-bound programs the constant halves are single words."""
    if COST_BOUND:
        return pair(Z128, pair(c64(typ_val << 32), pair(w2, Z32)))
    return pair(Z128, pair(pair(c32(typ_val), Z32), pair(w2, Z32)))

if HOT_PAD:
    PAD_HI = c128(0x80 << 120)
    def len_lo(bits): return c128(bits)
else:
    PAD_HI = pair(pair(c32(0x80000000), Z32), Z64)                   # 0x80 || 0^15
    def len_lo(bits): return pair(Z64, pair(Z32, c32(bits)))         # 0^12 || len as u32
if COST_BOUND:
    PAD_BLOCK_1024 = pair(word(256, 0x80 << 248), word(256, 1024))
else:
    PAD_BLOCK_1024 = pair(pair(PAD_HI, Z128), pair(Z128, len_lo(1024)))
def tail(bits_total):
    """last 128 bits of a block that ends a message 16 bytes before the block end."""
    if HOT_TAIL == 128:
        return c128((0x80 << 120) | bits_total)
    if HOT_TAIL == 64:
        return pair(c64(0x80 << 56), c64(bits_total))
    return pair(pair(c32(0x80000000), Z32), pair(Z32, c32(bits_total)))
TAIL896 = tail(896)
TAILLEAF = pair(pair(pair(c32(0x80000000), Z32), Z64), pair(Z64, pair(Z32, c32(8960))))   # second half of the last leaf block

IV = comp('unit', jet('sha_256_iv'))
define('sha_take', comp(jet('sha_256_block'), take('iden')))     # 2^256 x 2^512 -> 2^128
define('finish1024', comp(pair('iden', PAD_BLOCK_1024), 'sha_take'))

# ---------- witnesses ----------
LIST_LEVELS = [128, 64, 32, 16, 8, 4, 2, 1]
if FIXED_Q is None:
    E1_TY = '(2^128 * 2^128) * (2^32 * (2^256 * (2^256 * 2^32)))'
    SEED, ROOT, KEYIDX, MSG, R_, COUNTER = P('OOH'), P('OIH'), P('IOH'), P('IIOH'), P('IIIOH'), P('IIIIH')
    W_HEAD = define('w_head', 'witness', f'_ -> {E1_TY}')
    define('w_path1', 'witness', '_ -> 1 + 2^128')
    define('w_path2', 'witness', '_ -> 1 + 2^128')
    list_ty = None
    for n in reversed(LIST_LEVELS):
        opt = f'(1 + {T(128 * n)})'
        list_ty = opt if list_ty is None else f'({opt} * {list_ty})'
    define('w_list', 'witness', f'_ -> {list_ty}')
else:
    E1_TY = '(2^128 * 2^128) * (2^256 * (2^256 * 2^32))'
    SEED, ROOT, MSG, R_, COUNTER = P('OOH'), P('OIH'), P('IOH'), P('IIOH'), P('IIIH')
    KEYIDX = c32(FIXED_Q)
    W_HEAD = define('w_headq', 'witness', f'_ -> {E1_TY}')
    rest_len = min(FIXED_Q, 206) - 1
    chunks = [n for n in LIST_LEVELS if rest_len & n]
    if chunks:
        ty = None
        for n in reversed(chunks):
            ty = T(128 * n) if ty is None else f'({T(128 * n)} * {ty})'
        define('w_rest', 'witness', f'_ -> {ty}')
define('w_sig', 'witness', f'_ -> {T(8192)}')
define('w_path0', 'witness', '_ -> 2^128')
define('w_slroot', 'witness', '_ -> 2^128')

# ---------- E1 -> E2 ----------
# general: E2 = (digits, (keyidx, (root, ms)));  fixed: E2 = (digits, (root, ms))
define('midstate_e1', J('sha_256_block', pair(IV, pair(pair(SEED, Z128), zero(256)))))
msg1 = comp(J('sha_256_block', pair(J('sha_256_block', pair(IV, pair(adrs(c32(4), Z32, Z32, Z32), R_))), pair(pair(SEED, ROOT), MSG))), 'finish1024')
blk2 = pair(pair(pair(pair(COUNTER, c32(0x80000000)), Z64), Z128), pair(Z128, len_lo(544)))
define('digest_e1', comp(pair(J('sha_256_block', pair(IV, pair(adrs(c32(3), KEYIDX, Z32, Z32), pair(SEED, msg1)))), blk2), 'sha_take'))
if FIXED_Q is None:
    define('build_e2', pair('digest_e1', pair(KEYIDX, pair(ROOT, 'midstate_e1'))))
    DIGITS, KEYIDX2, RM2 = P('OH'), P('IOH'), P('IIH')      # RM = (root, ms)
    MS2 = P('IIIH')
else:
    define('build_e2', pair('digest_e1', pair(ROOT, 'midstate_e1')))
    DIGITS, KEYIDX2, RM2 = P('OH'), KEYIDX, P('IH')
    MS2 = P('IIH')

# ---------- WOTS chain: (hi, (lo, X)) -> 2^128 ; X = (y, Rest), Rest = (idx, (ms, pre64)) ----------
Y, IDX, MS, PRE64 = P('OH'), P('IOH'), P('IIOH'), P('IIIH')
def stepy(k):
    a = pair(Z128, pair(PRE64, pair(IDX, c32(k))))
    return comp(pair(MS, pair(a, pair(Y, TAIL896))), 'sha_take')
define('f2', stepy(2))
define('f1', pair(stepy(1), drop('iden')))
define('f0', pair(stepy(0), drop('iden')))
define('f12', comp('f1', 'f2'))
define('f012', comp('f0', 'f12'))
define('chain', case(drop(case(drop('f012'), drop('f12'))), drop(case(drop('f2'), drop(take('iden'))))))

# ---------- digit sum of 4 two-bit digits packed in a byte ----------
def AND8(a, b): return J('and_8', pair(a, b))
def SHR8(n, a): return J('right_shift_8', pair(c4(n), a))
def ADD8(a, b): return comp(J('add_8', pair(a, b)), drop('iden'))
y8 = ADD8(AND8('iden', c8(0x33)), AND8(SHR8(2, 'iden'), c8(0x33)))            # (d0+d1, d2+d3) as nibbles
define('dsum8', SHR8(4, comp(J('multiply_8', pair(y8, c8(0x11))), drop('iden'))), '2^8 -> 2^8')

# ---------- WOTS fold with threaded state: Sigma = ((st, pend), (Rest, sum)); level env = ((S, D), Sigma) ----------
def or32(a, n): return J('or_32', pair(a, c32(n)))
def add32(a, n): return comp(J('add_32', pair(a, c32(n))), drop('iden'))
c0 = comp(pair(P('OIOOH'), pair(P('OIOIH'), pair(P('OOOH'), P('IH')))), 'chain')
c1 = comp(pair(P('OIIOH'), pair(P('OIIIH'), pair(P('OOIH'), pair(or32(P('IOH'), 1), P('IIH'))))), 'chain')
define('g2', pair(c0, c1))                                        # ((S2, D2), Rest) -> (pk0, pk1)
g0 = comp(pair(pair(P('OOOH'), P('OIOH')), P('IIOH')), 'g2')
g1 = comp(pair(pair(P('OOIH'), P('OIIH')), pair(or32(P('IIOOH'), 2), P('IIOIH'))), 'g2')
st1 = J('sha_256_block', pair(P('IOOH'), pair(P('IOIH'), g0)))
sum1 = ADD8(P('IIIH'), comp(P('OIH'), 'dsum8'))
define('h4', pair(pair(st1, g1), pair(pair(add32(P('IIOOH'), 4), P('IIOIH')), sum1)))   # ((S4, D4), Sigma) -> Sigma'
prev = 'h4'
for n in [8, 16, 32, 64]:
    left = comp(pair(pair(P('OOOH'), P('OIOH')), P('IH')), prev)
    prev = define(f'h{n}', comp(pair(pair(P('OOIH'), P('OIIH')), left), prev))
pre64 = pair(Z32, KEYIDX2)
sigma0 = pair(pair(MS2, adrs(c32(1), KEYIDX2, Z32, Z32)), pair(pair(Z32, pair(MS2, pre64)), c8(0)))
foldin = pair(pair('w_sig', DIGITS), sigma0)
check_sum = J('verify', J('eq_8', pair(P('IIH'), c8(140))))
final_block = comp(pair(P('OOH'), pair(P('OIH'), TAILLEAF)), 'sha_take')
define('leaf_e2', comp(foldin, comp('h64', comp(pair(check_sum, 'iden'), drop(final_block)))))

# ---------- E3 = (leaf, RM), RM = (root, ms); path step (el, E4) -> E4 ----------
# Two equivalent layouts of E4 (the serialised size differs by a few bytes between the general and the fixed program):
#   layout A: E4 = ((h, node), RM)      layout B: E4 = (node, (h, RM))
E4_LAYOUT = 'B' if FIXED_Q is None else 'A'
for a in sys.argv[2:]:
    if a.startswith('--e4='): E4_LAYOUT = a.split('=')[1]
define('build_e3', pair('leaf_e2', P('IH')))
def SUB32(a, b): return comp(J('subtract_32', pair(a, b)), drop('iden'))
def INC32(a): return comp(J('increment_32', a), drop('iden'))
if E4_LAYOUT == 'A':
    # env (el, E4): el = OH, h = IOOH, node = IOIH, RM = IIH, ms = IIIH
    pathnode = comp(J('sha_256_block', pair(P('IIIH'), pair(adrs_t(2, P('IOOH')), pair(P('OH'), P('IOIH'))))), 'finish1024')
    define('path_step', pair(pair(INC32(P('IOOH')), pathnode), P('IIH')))
    def e4(el, h, node, rm): return pair(el, pair(pair(h, node), rm))
    NODE4, ROOT4, MS4 = P('OIH'), P('IOH'), P('IIH')
else:
    # env (el, E4): el = OH, node = IOH, h = IIOH, RM = IIIH, ms = IIIIH
    pathnode = comp(J('sha_256_block', pair(P('IIIIH'), pair(adrs_t(2, P('IIOH')), pair(P('OH'), P('IOH'))))), 'finish1024')
    define('path_step', pair(pathnode, pair(INC32(P('IIOH')), P('IIIH'))))
    def e4(el, h, node, rm): return pair(el, pair(node, pair(h, rm)))
    NODE4, ROOT4, MS4 = P('OH'), P('IIOH'), P('IIIH')
if FIXED_Q is None and NO_LAST:
    # general program for key indices 1..206 only (key index 207 gets its own tapleaf): no branch on the leaf position
    # E3' = (path0, (leaf, (keyidx, RM))): path0 = OH, leaf = IOH, keyidx = IIOH, RM = IIIH
    t = e4(P('IOH'), SUB32(c32(207), P('IIOH')), P('OH'), P('IIIH'))
    define('first_node_e3', comp(pair('w_path0', 'iden'), comp(t, 'path_step')))
elif FIXED_Q is None:
    # E3' = (path0, (leaf, (keyidx, RM))); branch env ((), E3'): path0 = IOH, leaf = IIOH, keyidx = IIIOH, RM = IIIIH
    is_last = J('eq_32', pair(P('IIOH'), c32(207)))
    not_last = e4(P('IIOH'), SUB32(c32(207), P('IIIOH')), P('IOH'), P('IIIIH'))
    last = e4(P('IOH'), c32(1), P('IIOH'), P('IIIIH'))
    define('first_node_e3', comp(pair('w_path0', 'iden'), comp(pair(is_last, 'iden'), comp(case(not_last, last), 'path_step'))))
else:
    # E3' = (path0, (leaf, RM)): path0 = OH, leaf = IOH, RM = IIH
    if FIXED_Q == 207:
        t = e4(P('OH'), c32(1), P('IOH'), P('IIH'))
    else:
        t = e4(P('IOH'), c32(207 - FIXED_Q), P('OH'), P('IIH'))
    define('first_node_e3', comp(pair('w_path0', 'iden'), comp(t, 'path_step')))

define('arr1', 'path_step')
for n in [2, 4, 8, 16, 32, 64, 128]:
    half = f'arr{n // 2}'
    define(f'arr{n}', comp(pair(P('OIH'), comp(pair(P('OOH'), P('IH')), half)), half))

if FIXED_Q is None:
    rest = None
    for n in reversed(LIST_LEVELS):
        if rest is None:
            body = case(P('IH'), f'arr{n}')
        else:
            some = comp(pair(P('IOH'), comp(pair(P('OH'), P('IIH')), f'arr{n}')), rest)
            body = comp(pair(P('OOH'), pair(P('OIH'), P('IH'))), case(drop(rest), some))
        rest = define(f'list{n}', body)
    some2 = comp('path_step', comp(pair('w_list', 'iden'), rest))
    after1 = comp('path_step', comp(pair('w_path2', 'iden'), case(P('IH'), some2)))
    define('paths_e4', comp(pair('w_path1', 'iden'), case(P('IH'), after1)))
else:
    if not chunks:
        define('paths_e4', 'iden')
    else:
        def step(cs):
            if len(cs) == 1:
                return f'arr{cs[0]}'
            return comp(pair(P('OIH'), comp(pair(P('OOH'), P('IH')), f'arr{cs[0]}')), step(cs[1:]))
        define('paths_e4', comp(pair('w_rest', 'iden'), step(chunks)))

# ---------- root check on E4 ----------
final = comp(J('sha_256_block', pair(MS4, pair(adrs(c32(16), Z32, Z32, Z32), pair(NODE4, 'w_slroot')))), 'finish1024')
define('root_check_e4', J('verify', J('eq_256', pair(pair(NODE4, final), pair(NODE4, ROOT4)))))

define('main', comp(W_HEAD, comp('build_e2', comp('build_e3', comp('first_node_e3', comp('paths_e4', 'root_check_e4'))))))

out = sys.argv[1]
with open(out, 'w') as f:
    for name, expr, ty in defs:
        f.write(f'{name} := {expr} : {ty}\n' if ty else f'{name} := {expr}\n')
print(f'wrote {out} ({len(defs)} definitions)')
