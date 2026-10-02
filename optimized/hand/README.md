# SHRINCS-L verifier as hand-written Simplicity DAGs

This directory contains a second implementation of both branches of `shrincs_verify` — the stateful (uXMSS) one and
the stateless (FORS + hypertree) one — written directly as Simplicity DAGs in rust-simplicity's human-readable
encoding instead of SimplicityHL, plus the generators, witness tools, a measurement harness and the test suite.
Same hash layouts, same signature format, same witness data as [`../shrincs_opt.simf`](../shrincs_opt.simf); only
the programs are different.

Headline (Liquid transaction, 1 input / 1 output + fee):

| | cost bound (mWU) | program B | witness B | padding B | tx vsize |
|---|---:|---:|---:|---:|---:|
| stateful q=1, `main` (HEAD) | 18,847,005 | 2905 | 1162 | 14,656 | 4,876 vB |
| stateful q=1, `optimize_fors` | 3,622,507 | 3930 | 1162 | 0 | 1,468 vB |
| stateful q=1, SimplicityHL rewrite (`../shrincs_opt.simf`) | 2,724,245 | 1461 | 1161 | 0 | 850 vB |
| **stateful q=1, this DAG, general program** (layout 1) | **2,136,142** | **846** | 1161 | 0 | **704 vB** |
| stateful q=1, this DAG, per-index program (layout 2) | 2,131,917 | 791 | 1156 | 0 | 746 vB |
| stateless, SimplicityHL rewrite | 10,018,140 | 2514 | 4393 | 2,987 | 2,669 vB |
| **stateless, this DAG** (layout 1, `--sum=32`) | **6,257,532** | **1750** | 4409 | 0 | **1,750 vB** |
| stateless, this DAG (layout 2, default) | 6,385,824 | 1665 | 4409 | 0 | 1,778 vB |

The transaction for the first stateful signature is 17.2 % smaller than with the SimplicityHL rewrite (704 vs
850 vB), over the whole life of a key (207 signatures) the average transaction is 15.2 % (layout 1) or 20.1 %
(layout 2) smaller, and the stateless transaction is 34 % smaller (1,750 vs 2,669 vB). The remaining bytes are now
dominated by the signatures themselves: 704 vB = 174 vB base transaction + 290 vB witness (signature, key, message)
+ 212 vB program + 25 vB script + control block + 3 vB varints; 1,750 vB = 174 + 1,102 witness + 438 program + 33 +
3, with the cost bound 1.4 % under the budget.

## Results for every key index

`results/full_table.{json,csv}` has all 207 key indices; a few rows (vB per transaction):

| key index q | auth nodes | SimplicityHL rewrite | layout 1 (3 tapleaves) | layout 2 (per-index tapleaf) |
|---:|---:|---:|---:|---:|
| 1 | 1 | 850 | **704** (−17.2 %) | 746 (−12.2 %) |
| 2 | 2 | 889 | **718** (−19.2 %) | 752 (−15.4 %) |
| 3 | 3 | 988 | 808 (−18.2 %) | **758** (−23.3 %) |
| 10 | 10 | 1,029 | 841 (−18.3 %) | **798** (−22.4 %) |
| 20 | 20 | 1,072 | 886 (−17.4 %) | **846** (−21.1 %) |
| 50 | 50 | 1,205 | 1,019 (−15.4 %) | **969** (−19.6 %) |
| 100 | 100 | 1,444 | 1,220 (−15.5 %) | **1,182** (−18.1 %) |
| 150 | 150 | 1,744 | 1,481 (−15.1 %) | **1,386** (−20.5 %) |
| 206 | 206 | 1,947 | 1,663 (−14.6 %) | **1,615** (−17.1 %) |
| 207 | 206 | 2,084 | **1,575** (−24.4 %) | 1,620 (−22.3 %) |
| average over 1..207 | | 1,495 | 1,268 (−15.2 %) | **1,195** (−20.1 %) |
| stateless | | 2,669 | **1,750** (−34.4 %) | 1,778 (−33.4 %) |

The stateless leaf is `programs/stateless.simpl` (or `stateless_sum32.simpl`, see below) in its own tapleaf: depth 2
in layout 1, depth 8 in layout 2. Its cost bound sits right at the natural budget, so it is the one program where
the control-block depth and the checksum granularity still trade against each other (both variants are generated
and measured by `full_table.py`).

### Tapleaf layouts

A `case` whose other branch is not taken costs 32 B on chain (the hidden CMR), exactly what one level of the taproot
tree costs in the control block. So every decision that depends on the key index (is it the last leaf? how long is
the auth path?) can be made either inside the program or by choosing a tapleaf, at the same price, and the
specialised programs are smaller because they also lose the option bits and the code for the other case.

* **Layout 1 — 3 tapleaves.** `programs/general.simpl` (key indices 1..206, key index in the witness, auth path as
  `path0 + Option + Option + List<u128,256>`) at depth 1; `programs/stateful_q207.simpl` (index 207 is the only
  leaf that is a right child) and the stateless program at depth 2. Best for the first two signatures.
* **Layout 2 — 208 tapleaves.** One program per key index (`gen_stateful_dag.py --fixed-q=N`; key index a constant,
  auth-path length fixed, no branches at all) plus the stateless program, balanced tree, control block 289 B.
  Best from the third signature on and on average; the 207 CMRs are computed once at key generation.
* A skewed tree is also possible: index-1 program at depth 1 (697 vB), index-2 at depth 2 (703 vB), everything
  else at depth 10 (+16 vB each versus layout 2); likewise the stateless leaf can sit at depth 1 (−56 vB for it,
  +8 vB for every stateful spend).

For auth paths longer than ~80 nodes the spend becomes CPU-budget bound; the per-index programs then use
`--hot-pad` (SHA padding block from 128-bit words: −4.8k mWU per path node for +28 B) and, for the longest paths,
`--nested-chain` (−200k mWU for +31 B); `full_table.py` picks the best variant per index. Padding stays below
30 B for every key index in layout 2 (up to 518 B in layout 1, whose general program is tuned for short paths).

## What the DAG does differently

The SimplicityHL rewrite was already at the optimum *of what the SimplicityHL code generator emits*: every `let`
copies the environment twice, every `match` copies it once, every function call rebuilds the environment from its
parameters, and witnesses can only be read in `main`. Writing the DAG by hand removes those copies and lets the data
sit where the hot loop needs it:

* **WOTS chain.** `chain : (hi, (lo, (y, Rest))) -> pk` dispatches on the two digit bits with two nested `case`
  nodes that consume the bits in place (no environment copy), and the three step functions are shared nodes:
  the four branches are `f0;f1;f2`, `f1;f2`, `f2`, `id`. One chain is 20.8k mWU for the 3-step bound
  (33k in a first version of this DAG that tested the three steps one after the other). A step is one `sha_256_block` on
  `ADRS || y || 0x80 .. len` with the midstate of `seed || 0^48` carried in `Rest`.
* **One fold for leaf, index and checksum.** The 64 chains are folded by halving (`g2`, `h4`, `h8` … `h64`), and a
  single state `Sigma = ((st, pend), ((idx, (ms, pre64)), sum))` threads the streamed SHA-256 of the leaf (`st` =
  state, `pend` = the half block waiting for two more public keys), the chain index and the digit sum through the
  levels. The checksum of the 64 base-4 digits is accumulated per group of four digits with a SWAR on one byte
  (`dsum8`, 23 nodes, 3 bytes of constants) instead of a separate 137 B pass over the 128-bit digest.
* **Constants.** All-zero words and the SHA padding blocks are assembled from a shared 32-bit zero word and the few
  constants the program needs anyway (`0x80000000`, the type tags); the only wide words are the 128-bit zero and the
  chain-step padding tail in the hot loop. 81 B of word data instead of 351 B.
* **Witnesses.** `w_head` is one witness node of type `((seed, root), (keyidx, (message, (r, counter))))`, read
  once; `w_sig` is one 8192-bit word; the auth path is `w_path0` plus two options and a list, read exactly where
  they are consumed. (A witness node may be reachable by only one path in Simplicity, which is why the
  first-node branch fetches `w_path0` before the `case`.)
* **Auth path.** `path_step : (el, E4) -> E4` with `E4 = (node, (h, (root, ms)))` is the shared primitive for the
  first node and for every array/list level; the first node only builds the `(el, E4)` pair in the right order.

Where the 846 B of the general program go (q = 1): message digest + midstate 186 B, WOTS fold incl. checksum and
leaf 492 B, first auth node 81 B, optional-path handling 41 B (of which 32 B hidden CMR), root check 46 B.
Where the 2.14 M mWU go: 64 chains × 20.8k = 1.33 M, fold plumbing (environment movement, 16 SHA blocks, checksum)
0.69 M, everything else 0.08 M. The cost bound sits just under the natural budget for q = 1 (2,136 vs 2,163 WU), so
further byte savings in the hot loop would need matching cost savings; the design notes in
`gen_stateful_dag.py` list the knobs (`--hot-zero`, `--hot-tail`, `--hot-pad`, `--cost-bound`, `--nested-chain`).

### The stateless program

`gen_stateless_dag.py` builds the stateless verifier (5 FORS trees of height 22, FORS pk, two XMSS layers with
64 WOTS chains and 12 auth nodes each, final root) from the same pieces, with a few additions that matter because
this spend is CPU-budget bound (4.4 KB of signature buys a budget of ~6.3 M mWU):

* **Nested chain steps.** The three WOTS steps of a chain are nested expressions over one environment: the inner
  step's 256-bit SHA state feeds the outer block through `comp inner (pair (take iden) tail)`, so nothing is rebuilt
  between steps and the result is truncated once per chain (18.6k mWU per chain against 22.2k for the same chain written as the composition
  `f0;f1;f2`; also available in the stateful generator as `--nested-chain`).
* **One auth-path step for everything.** `path_step : (Left(el) | Right(el), PS) -> PS` with
  `PS = ((adrs_hi, (adrs_mid, ms)), (node, (height, parent)))` serves the 110 FORS nodes and the 24 XMSS nodes:
  the FORS and XMSS node hashes differ only in the ADRS prefix carried in the state. The auth-path elements carry
  their side as a sum tag (`Left` = the node in hand is the left child), so the `case` dispatches on the element
  itself, with no environment copy and no bit extraction. The tags are not checked against the index and do not
  need to be: the ADRS of every node contains `(height, index >> height)`, so a wrong tag changes the hash input and
  the root no longer matches (every tag flip is rejected in the tamper tests). The tags cost 134 bits of witness.
* **Shared tree and layer nodes.** `fors_tree` is one node applied to the five trees (each read from its own
  witness node), rotating 5-tuples of roots and leaf indices through its state; `xmss_layer` is one node applied to
  both layers, carrying `(message, (key_idx, (layer || tree, (tree_idx, (seed, (ms, pk_root))))))` and producing
  the next layer's context (`layer + 1`, `tree >> 12`).
* **Constants.** The SHA padding block of the path nodes is a single 512-bit word (the lean form would cost 1.3 M
  mWU more); everything else is assembled from a 32-bit zero word. `--sum=32` moves the checksum accumulation from
  groups of 4 digits to groups of 32 (64-bit SWAR): −130k mWU for +85 B, which wins when the leaf sits at depth 2.

Where the 6.26 M mWU go (`--sum=32`): two XMSS layers 4.1 M (64 chains × 18.6k = 1.19 M each, WOTS fold plumbing
0.6 M each, 12 path nodes 0.19 M each), five FORS trees 2.0 M (22 path nodes × 16.5k incl. the fold, plus the
leaf), digest, FORS pk and the final root 0.09 M. A path node is 12.4k mWU: the two SHA blocks with their input
frames 8.7k (the jets themselves are 1.7k of that; the rest is block assembly, the padding word and the truncation),
the `(height + 1, parent >> 1)` update 2.3k, the state copy 0.8k, glue 0.6k.

## Files

| path | what |
|---|---|
| `gen_stateful_dag.py` | stateful generator: emits the program in rust-simplicity's human-readable encoding (general, `--no-last`, `--fixed-q=N`, constant knobs) |
| `gen_stateless_dag.py` | stateless generator (`--sum=4|32`, `--g2`, `--lean-constants`) |
| `programs/general.simpl` | layout-1 general stateful program (key indices 1..206), CMR `d6a4d30d…6f6d842b8` |
| `programs/stateful_q207.simpl` | index-207 program (`--fixed-q=207 --hot-pad --nested-chain`) |
| `programs/stateful_q{1,2,10,100}.simpl` | examples of per-index programs (q=100 with `--hot-pad --nested-chain`) |
| `programs/stateless.simpl`, `stateless_sum32.simpl` | stateless program, CMR `9155887d…dbbc4c1c` / `491521b3…b2621f55` |
| `make_witness.py`, `make_witness_sl.py` | `vectors*.jsonl` → witness specs for the harness |
| `witnesses/` | witness specs for q = 1, 2, 10, 100, 207 and two stateless vectors |
| `ref_verify.py`, `ref_verify_sl.py` | plain-Python references of both verifications (hashlib); the stateless one also yields the auth-path tags |
| `tamper.py`, `tamper_sl.py` | negative tests (bit flips in every witness field, swapped/dropped auth nodes, flipped tags, swapped trees/layers) |
| `validate_all.sh` | full test run (references, all vectors with every program variant, tamper tests, decode round trips) |
| `full_table.py` | sizes for all 207 key indices, both layouts and the stateless leaf → `results/full_table.{json,csv}` |
| `../tools/harness/src/bin/hand.rs` | harness: parse, bind witnesses, prune, execute, measure, decode round trip |
| `../vectors/vectors_stateless.jsonl` | 40 more stateless signatures (own key) from `shrincs-cpp` for the stateless tests |

## Witness layout

General program (`w_head`, `w_sig`, `w_path0`, `w_path1`, `w_path2`, `w_list`, `w_slroot`):

```
w_head   : ((seed, root), (key_idx, (message, (r, counter))))     u128,u128, u32, u256, u256, u32
w_sig    : 2^8192 = the 64 WOTS chain elements, element 0 first
w_path0  : u128  first auth node
w_path1  : 1 + 2^128  second auth node (None for key index 1)
w_path2  : 1 + 2^128  third auth node
w_list   : (1 + [u128;128]) * ((1 + [u128;64]) * ... * (1 + [u128;1]))   remaining auth nodes, chunk n present
           iff bit n of the remaining length is set, elements in order
w_slroot : u128  root of the stateless half (hashed with the uXMSS root into the public key root)
```

Per-index program (`--fixed-q=N`): `w_headq = ((seed, root), (message, (r, counter)))`, `w_sig`, `w_path0`,
`w_rest` = the remaining `min(N,206)−1` auth nodes as nested power-of-two chunks (largest first), `w_slroot`.
Witness bytes: 1161 (general) / 1156 (fixed) for q = 1, +16 per further auth node.

Stateless program: `w_head = ((seed, root), (message, r))`, `w_fors0..4 = (sk, (A16, (A4, A2)))` with `A_n` =
`n` auth nodes of type `2^128 + 2^128` (the tag is the side, see above), `w_x0`/`w_x1 = (counter, (sig, (A8, A4)))`,
`w_slroot` (uXMSS root). 4409 bytes: the 4392 bytes the SimplicityHL witness carries plus the 134 tag bits. The
per-layer randomness `r` of the XMSS layers is not part of the witness (the verifier never reads it), as before.

In a real spend the message would be `jet::sig_all_hash()` and `seed`/`root` program constants
(−64 B witness, +32 B program, 698 vB for q = 1); the interface is kept identical to the repo's verifier so that
the numbers compare like for like.

## Validation

* `ref_verify.py` / `ref_verify_sl.py` (independent Python implementations of the hash layouts) accept 207/207
  stateful and 43/43 stateless vectors (`../vectors/vectors_full.jsonl` and `vectors_stateless.jsonl`, generated by
  `shrincs-cpp` @ fde3603, `-DSHRINCS_L`).
* The general program accepts the 206 vectors it is meant for, the index-207 program its vector, every per-index
  program (cold, `--hot-pad`, `--hot-pad --nested-chain`) its vector: 621/621 runs. Both stateless variants accept
  all 43 stateless vectors.
* Tampered witnesses are rejected: 24–28 cases per stateful program (flipped nibbles in seed, root, key index,
  message, r, counter, chain elements, auth nodes, stateless root; swapped chain elements; dropped/added/rotated auth
  nodes), for the general program at q = 1, 10, 206 and per-index programs at q = 1, 10, 207; 53 cases per
  stateless program (every head field, FORS secrets, FORS and XMSS auth nodes and their tags, counters, chain
  elements, swapped trees and swapped layers) on two vectors. A checksum constant of 141 instead of 140 rejects all
  206 valid vectors of the general program; `dsum8` was checked against all 256 inputs.
* The serialised program + witness bytes decode back to the same CMR and execute (`hand … --roundtrip`); the cost
  in the tables is the post-decode (consensus) bound.
* Size model: `../tools/txsize.py` (Elements budget rule: witness-stack bytes + 50 WU; annex padding when the bound
  is larger), control block 33 + 32·depth.

## Reproducing

```
cd ../tools/harness && cargo build --release --bin hand          # SimplicityHL master @ 351eb06 / simplicity-lang 0.9.0
cd ../../hand
python3 gen_stateful_dag.py programs/general.simpl --no-last
python3 make_witness.py ../vectors/vectors_full.jsonl witnesses_all
../tools/harness/target/release/hand programs/general.simpl witnesses_all/stateful_q1.hand.json --nodes
python3 gen_stateless_dag.py programs/stateless.simpl
python3 make_witness_sl.py ../vectors/vectors_full.jsonl witnesses_sl
../tools/harness/target/release/hand programs/stateless.simpl witnesses_sl/stateless_0.hand.json --attr
python3 -c "import sys; sys.path.insert(0,'../tools'); from txsize import model; print(model(2136142, 846, 1161, 32))"
./validate_all.sh                                               # ~1.5 min
python3 full_table.py                                           # ~1 min, writes results/
```

The programs are plain text; `rust-simplicity`'s `Forest::parse` reads them, and `simplicity-lang`'s human
encoding needs the `human_encoding` feature (enabled in the harness manifest).

## What is left

* Both programs now sit at their budgets: the stateful one is bytes-bound (every byte saved in the hot loop needs a
  matching 1k mWU), the stateless one is within 1.4 % of its budget. Per chain step the floor is roughly 4.7k mWU
  (SHA 871 + block assembly + frame copies) against ~5.5k now, and a path node could lose maybe 1–2k of its 12.4k;
  all of it is worth a few percent of cost, not of bytes.
* The stateless spend is 63 % signature data (4.4 KB); the five FORS auth paths (1.8 KB) and the two 1 KB WOTS
  signatures are fixed by the parameters (k = 6 with one index ground to zero, a = 22, w = 4).
* Nothing on the parameter side: a chain element costs 16 B of witness and a bound hash step ~6 B of budget, so
  w = 4 remains the cheapest Winternitz choice under this cost model.
