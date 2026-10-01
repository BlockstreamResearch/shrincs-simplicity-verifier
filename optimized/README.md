# SHRINCS Simplicity verifier — size/cost optimized

Drop-in reimplementation of `shrincs/shrincs.simf` from
[BlockstreamResearch/shrincs-simplicity-verifier](https://github.com/BlockstreamResearch/shrincs-simplicity-verifier)
(`main` @ 9d3791a, FORS variant, SHRINCS-L parameters) with the same hash layouts and the same
accept/reject behaviour, written for the Liquid/Elements cost model.

All numbers below were measured with the SimplicityHL compiler (master @ 351eb06, simplicity-lang 0.9.0,
same cost model as the version bundled in the repo) and a transaction model for a 1-input / 1-output + fee
explicit Liquid transaction (174 base bytes, `weight = 3·base + total`, `vsize = ceil(weight / 4)`).

## Short answer to the "2846 vB" question

2846 vB is not a lower bound and not an upper bound — it is simply a number in between what the repo
does today and what the same scheme costs when the Simplicity program is written for the cost model.

* The 1092-byte signature is *witness* data: it weighs 1092 WU = **273 vB**, not 1092 vB.
* What makes the current transactions big is not data but the **CPU budget rule** of Simplicity on
  Elements (`src/script/interpreter.cpp`): `budget = witness-stack bytes + 50` and the program's static
  cost bound (milli-WU) must be ≤ `budget · 1000`. With `main`'s program the q=1 stateful verification has
  a bound of 18.85 M mWU, so ~14.7 KB of padding has to be added to the witness. That is where ~4,876 vB
  (9,439 vB in the older performance report) come from.
* 2846 vB corresponds to a witness stack of ~10.7 KB, i.e. a cost bound ≤ ~10.7 M mWU — a 43% reduction
  from `main`, which is clearly reachable (both `optimize_fors` and this work are far below it).
* This work needs **850 vB** for q=1 with no padding at all: 1161 B of signature data + 1461 B of program + 74 B of
  script/control/prefixes = 2696 B of witness stack (674 vB) plus a 174 B base transaction.

## Results

| vector | version | cost bound (mWU) | program B | witness B | padding B | witness stack B | tx vsize (vB) |
|---|---|---:|---:|---:|---:|---:|---:|
| stateful q=1 | main (HEAD) | 18,847,005 | 2905 | 1162 | 14,656 | 18,800 | **4,876** |
| stateful q=1 | optimize_fors | 3,622,507 | 3930 | 1162 | 0 | 5,166 | **1,468** |
| stateful q=1 | this work | 2,724,245 | 1461 | 1161 | 0 | 2,696 | **850** |
| stateful q=2 | main (HEAD) | 18,900,825 | 2908 | 1178 | 14,690 | 18,853 | 4,889 |
| stateful q=2 | optimize_fors | 3,665,103 | 3933 | 1178 | 0 | 5,185 | 1,472 |
| stateful q=2 | this work | 2,746,381 | 1600 | 1177 | 0 | 2,851 | 889 |
| stateful q=10 | main (HEAD) | 19,303,947 | 2950 | 1306 | 14,923 | 19,256 | 4,990 |
| stateful q=10 | optimize_fors | 3,978,433 | 3971 | 1306 | 0 | 5,351 | 1,514 |
| stateful q=10 | this work | 2,949,895 | 2030 | 1306 | 0 | 3,410 | 1,029 |
| stateful q=100 | main (HEAD) | 23,844,013 | 3006 | 2746 | 17,968 | 23,797 | 6,125 |
| stateful q=100 | optimize_fors | 7,508,339 | 4022 | 2746 | 616 | 7,461 | 2,041 |
| stateful q=100 | this work | 5,119,931 | 2085 | 2746 | 164 | 5,070 | 1,444 |
| stateful q=207 | main (HEAD) | 29,194,000 | 3077 | 4442 | 21,550 | 29,146 | 7,463 |
| stateful q=207 | optimize_fors | 11,668,682 | 4094 | 4442 | 3,008 | 11,621 | 3,081 |
| stateful q=207 | this work | 7,678,200 | 2111 | 4442 | 1,001 | 7,631 | 2,084 |
| stateless | main (HEAD) | 49,160,743 | 4101 | 4457 | 40,478 | 49,113 | 12,454 |
| stateless | optimize_fors | 16,224,611 | 5035 | 4457 | 6,608 | 16,177 | 4,220 |
| stateless | this work | 10,018,140 | 2514 | 4393 | 2,987 | 9,971 | 2,669 |
The stateful transaction is padding-free up to q = 82; the full per-q curve is in `vectors/curve.json`.
`optimize_fors` numbers are for branch head b4da848 measured with the same harness and the same signatures.

## Where the cost goes (and why the rewrite helps)

The Simplicity cost model charges 100 mWU per executed combinator plus the bit width of every value that is
copied (`iden`) or allocated as a `comp` frame. In `main`'s q=1 program only ~0.25 M of the 18.85 M mWU are
the SHA-256 jets; the rest is what the SimplicityHL code generator emits around them:

* every `let` copies the whole environment twice and every `match` copies it once (`comp (pair expr iden) …`);
* every variable access is a chain of `take`/`drop` nodes plus a copy of the value;
* the environment of `main` contains the whole proof, whose *type* is 74k bits wide because
  `List<u128, 512>` alone is 65k bits — so each statement in that scope costs ~150k mWU;
* the WOTS chain loop (`for_while` with a u2 counter) and the `map_arr` recursion copy large arrays at every level.

One structural fact limits every implementation: the chain code is one shared node inside a fold, so after
pruning both branches of the digit `match` survive and the static bound charges the worst case,
3 hash steps per chain (192), although only 52 execute. The hashing floor is therefore ~1.6 M mWU per
WOTS instance in SimplicityHL, and the rest is plumbing that this rewrite removes.

What the rewrite does differently:

* witnesses are split by use (`HEAD`, `SIG`, `PATH0`, `PATH`, `ROOT_PART`, …) and every big value is passed
  straight from `main` to the function that consumes it, so no wide type ever sits in an environment;
* each fold step does a single destructuring `let`; all intermediate results are nested into the result tuple;
* the message digits come from a free cast of the digest (`u128 → (bool, bool) × 64`), chains are
  straight-line hash expressions behind two bit matches, and the leaf hash is streamed inside the fold accumulator;
* the WOTS+C checksum is a bit-parallel field sum of the digest (two `multiply_64` tricks), not 64 additions;
* the first auth node is its own witness, so the "rightmost leaf" case is one `match` and the fold step has none; the
  second and third auth nodes are `Option<u128>` witnesses and the list fold only exists inside their `Some` branches,
  so a q=1 or q=2 spend never carries the fold's eight pruned levels (8 × 32 B of hidden CMRs);
* the stateless branch applies the same rules to FORS (5 trees × 22 nodes), the hypertree index extraction
  (64-bit shifts instead of a 256-bit shifter), and the two XMSS layers; `full_right_shift_32_1` yields the
  parent index and the direction bit in one jet; `add_32`/shift results are carried as raw pairs in the accumulator;
* constants are built from shared 64/128-bit halves so that the pruned program carries fewer `word` bytes.

Each pruned `case` branch costs a 32-byte hidden CMR in the program; the list fold over the auth path has 8
levels (covering every path length ≤ 207 needs a full binary decomposition), which is why q ≥ 3 carries 256 B
more program than q = 1. The q=1 program contains only three hidden nodes (the unused stateless branch, the
unused `Some` branch of the optional second node, and the unused ordering for the rightmost leaf). A tapleaf
dedicated to q = 1 would now save only ~13 vB more, so one generic program is enough.

## Where the remaining bytes are, and what is left

For q = 1 the 850 vB split into 174 vB of base transaction (fixed by Liquid), 290 vB of signature data
(fixed by the scheme), 18 vB of taproot overhead and 368 vB of program. The program's cost bound now sits
about 20 WU under the budget, so the two quantities trade one-for-one from here: every code-sharing
rewrite I tried (a shared chain-step function, a fold with the digest rotated in the accumulator, zipped
witness layouts) saves 15–40 B of program and costs 100–400k mWU, i.e. more padding than it saves.
The SimplicityHL formulation is at its optimum for this structure. What could still move the number:

* a hand-generated Simplicity DAG (bypassing SimplicityHL's environment-passing code generation) — an
  estimated 25–35% smaller program and ~40% lower cost, i.e. roughly 720–750 vB for q = 1; a multi-day
  project with its own generator and test suite;
* taking the message from `jet::sig_all_hash()` instead of the witness in a real spend: −32 B (−8 vB);
* nothing on the parameter side: under this cost model a chain element costs 16 B of witness and a bound
  hash step ~8 B of budget, which makes w = 4 (SHRINCS-L) the cheapest Winternitz choice already.

## Witness layout

```
IS_STATEFUL : bool
stateful  : HEAD = (pk, key_idx, message, r, counter), SIG = [u128; 64], PATH0 = u128 (first auth node),
            PATH = List<u128, 256> (remaining auth nodes), ROOT_PART = u128 (stateless root)
stateless : HEAD_SL = (pk, message, r), FORS = [(sk, [u128; 22]); 5], X{0,1}_COUNTER = u32,
            X{0,1}_SIG = [u128; 64], X{0,1}_PATH = [u128; 12], ROOT_PART_SL = u128 (stateful root)
```
The branch that is not taken is pruned to a single hidden node and its witness values are not encoded, so the
on-chain witness is the signature plus 1 bit. (`r` of the two XMSS signatures is unused by the verifier and is
not carried, which is why the stateless witness is 64 B smaller than before.)

`tools/convert_wit.py` converts the repo's single-`PROOF` witness files; `tools/vectors_to_wit.py` converts raw
signatures from the C++ signer into both formats.

## Validation

* `examples/` contains the repo's own example witnesses converted to the new layout (and two generated ones).
* `vectors/vectors_full.jsonl`: a key plus 207 stateful signatures (q = 1 … 207, i.e. every leaf including the
  two special last ones) and 3 stateless signatures, produced with `shrincs-cpp` @ fde3603 (`-DSHRINCS_L`,
  the commit that matches the repo's witnesses) via `tools/gen_vectors.cpp`. All 210 verify with `main`'s
  program and with this program (`check` reports identical verdicts for every vector).
* Tamper tests (`tools/tamper_test.py`): every component of the stateful and stateless witnesses was modified
  (pk, key index, message, r, counter, first/last chain element, each auth node incl. the optional ones, FORS
  sk/path, XMSS counters, signature elements and paths, stateless root) — all rejected; a q=2 signature presented
  with the second node absent is rejected as well.
* Both compilers give the same CMR for `shrincs_opt.simf`
  (`59e27a35b311e877790cd797ca3567bf10b59751129134762bc112d3fbd76177`).

### Toolchain note

The `simfony` binary bundled in the repo is SimplicityHL 31783fe built against rust-simplicity 7654c80 (0.6/0.7
era). That rust-simplicity has a pruning bug (fixed in simplicity-lang 0.7.1,
BlockstreamResearch/rust-simplicity#362): for some inputs the pruned program takes a branch that was pruned
("Execution reached a pruned branch") — it happens with the repo's own q=1 example and with q=2/q=207 here.
Witnesses built with that binary can be invalid on-chain. Use SimplicityHL ≥ 0.8.0 (simplicity-lang 0.9.0,
which also prunes with maximal sharing, #379) to produce the on-chain program.

## Reproducing

```
# compile + run + prune + measure one witness (needs a SimplicityHL checkout, see tools/harness/Cargo.toml)
cd tools/harness && cargo build --release
./target/release/check ../../shrincs_opt.simf ../../examples/stateful_q1.wit
./target/release/measure ../../shrincs_opt.simf ../../examples/stateful_q1.wit   # detailed cost attribution

# transaction size model
python3 tools/txsize.py vectors/comparison.json   # or import txsize.model(cost, program_bytes, witness_bytes)

# test vectors: build shrincs-cpp @ fde3603 with tools/gen_vectors.cpp
g++ -std=c++17 -O2 -DSHRINCS_L gen_vectors.cpp src/*.cpp -I include -lssl -lcrypto -o gen && ./gen 207 3 vectors.jsonl
python3 tools/vectors_to_wit.py vectors.jsonl vec/
```

## Further options (not applied, to keep the interface identical to the repo)

* Key-bound program: embed `pk_seed`/root as constants → −48 B witness, no final root hash; the program is then
  the key (which it already is via the taproot commitment).
* Take the message from `jet::sig_all_hash()` instead of the witness → −32 B witness.
* Dedicated tapleaves per branch / per range of q (worth ~13 vB at q = 1 now; more for q ≥ 3 if a small `List<u128, 16>` leaf is added).
