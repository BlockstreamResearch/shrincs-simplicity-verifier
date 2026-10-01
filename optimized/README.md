# SHRINCS Simplicity verifier — size/cost optimized

Drop-in reimplementation of `shrincs/shrincs.simf` from
[BlockstreamResearch/shrincs-simplicity-verifier](https://github.com/BlockstreamResearch/shrincs-simplicity-verifier)
(`main` @ 9d3791a, FORS variant, SHRINCS-L parameters) with the same hash layouts and the same
accept/reject behaviour, written for the Liquid/Elements cost model.

All numbers below were measured with the SimplicityHL compiler (master @ 351eb06, simplicity-lang 0.9.0,
same cost model as the version bundled in the repo) and a transaction model for a 1-input / 1-output + fee
explicit Liquid transaction (173 base bytes, `weight = 3·base + total`, `vsize = ceil(weight / 4)`).

## Short answer to the "2846 vB" question

2846 vB is not a lower bound and not an upper bound — it is simply a number in between what the repo
does today and what the same scheme costs when the Simplicity program is written for the cost model.

* The 1092-byte signature is *witness* data: it weighs 1092 WU = **273 vB**, not 1092 vB.
* What makes the current transactions big is not data but the **CPU budget rule** of Simplicity on
  Elements (`src/script/interpreter.cpp`): `budget = witness-stack bytes + 50` and the program's static
  cost bound (milli-WU) must be ≤ `budget · 1000`. With `main`'s program the q=1 stateful verification has
  a bound of 18.85 M mWU, so ~14.7 KB of padding has to be added to the witness. That is where ~4,875 vB
  (9,439 vB in the older performance report) come from.
* 2846 vB corresponds to a witness stack of ~10.7 KB, i.e. a cost bound ≤ ~10.7 M mWU — a 43% reduction
  from `main`, which is clearly reachable (both `optimize_fors` and this work are far below it).
* This work needs **933 vB** for q=1 with no padding at all (838 vB with a tapleaf dedicated to q=1); the padding-free floor for this signature
  encoding is `(signature + program + 65) / 4 ≈ 760 vB` of witness plus the base transaction.

## Results

| vector | version | cost bound (mWU) | program B | witness B | padding B | witness stack B | tx vsize (vB) |
|---|---|---:|---:|---:|---:|---:|---:|
| stateful q=1 | main (HEAD) | 18,847,005 | 2905 | 1162 | 14,656 | 18,800 | **4,875** |
| stateful q=1 | optimize_fors | 3,622,507 | 3930 | 1162 | 0 | 5,166 | **1,467** |
| stateful q=1 | this work | 2,732,061 | 1797 | 1162 | 0 | 3,033 | **933** |
| stateful q=1 | this work, q=1-only tapleaf (2-leaf tree) | 2,701,199 | 1364 | 1161 | 20 | 2,652 | **838** |
| stateful q=2 | main (HEAD) | 18,900,825 | 2908 | 1178 | 14,690 | 18,853 | 4,888 |
| stateful q=2 | optimize_fors | 3,665,103 | 3933 | 1178 | 0 | 5,185 | 1,471 |
| stateful q=2 | this work | 2,751,995 | 1882 | 1178 | 0 | 3,134 | 959 |
| stateful q=10 | main (HEAD) | 19,303,947 | 2950 | 1306 | 14,923 | 19,256 | 4,989 |
| stateful q=10 | optimize_fors | 3,978,433 | 3971 | 1306 | 0 | 5,351 | 1,513 |
| stateful q=10 | this work | 2,944,365 | 1937 | 1306 | 0 | 3,317 | 1,004 |
| stateful q=100 | main (HEAD) | 23,844,013 | 3006 | 2746 | 17,968 | 23,797 | 6,124 |
| stateful q=100 | optimize_fors | 7,508,339 | 4022 | 2746 | 616 | 7,461 | 2,040 |
| stateful q=100 | this work | 5,116,251 | 2004 | 2746 | 242 | 5,067 | 1,442 |
| stateful q=207 | main (HEAD) | 29,194,000 | 3077 | 4442 | 21,550 | 29,146 | 7,462 |
| stateful q=207 | optimize_fors | 11,668,682 | 4094 | 4442 | 3,008 | 11,621 | 3,080 |
| stateful q=207 | this work | 7,674,876 | 2016 | 4442 | 1,092 | 7,627 | 2,082 |
| stateless | main (HEAD) | 49,160,743 | 4101 | 4457 | 40,478 | 49,113 | 12,453 |
| stateless | optimize_fors | 16,224,611 | 5035 | 4457 | 6,608 | 16,177 | 4,219 |
| stateless | this work | 10,006,268 | 2521 | 4393 | 2,968 | 9,959 | 2,665 |
The stateful transaction is padding-free up to q = 69; the full per-q curve is in `vectors/curve.json`.
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
* the first auth node is its own witness, so the "rightmost leaf" case is one `match` and the fold step has none;
* the stateless branch applies the same rules to FORS (5 trees × 22 nodes), the hypertree index extraction
  (64-bit shifts instead of a 256-bit shifter), and the two XMSS layers; `full_right_shift_32_1` yields the
  parent index and the direction bit in one jet; `add_32`/shift results are carried as raw pairs in the accumulator;
* constants are built from shared 64/128-bit halves so that the pruned program carries fewer `word` bytes.

Each pruned `case` branch costs a 32-byte hidden CMR in the program; the list fold over the auth path has 8
levels, so 256 B of the q=1 program are hidden nodes. That is inherent: covering every path length ≤ 207 needs
a full binary decomposition. A tapleaf dedicated to q = 1 avoids the fold entirely (`shrincs_opt_q1leaf.simf`,
1364 B); the second leaf of the tree costs 32 B of control block.

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

`tools/convert_wit.py` converts the repo's single-`PROOF` witness files (`examples/shrincs/*.wit`); `tools/vectors_to_wit.py` converts raw
signatures from the C++ signer into both formats.

## Validation

* `examples/` contains the repo's own example witnesses converted to the new layout (and two generated ones).
* `vectors/vectors_full.jsonl`: a key plus 207 stateful signatures (q = 1 … 207, i.e. every leaf including the
  two special last ones) and 3 stateless signatures, produced with `shrincs-cpp` @ fde3603 (`-DSHRINCS_L`,
  the commit that matches the repo's witnesses) via `tools/gen_vectors.cpp`. All 210 verify with `main`'s
  program and with this program (`check` reports identical verdicts for every vector).
* Tamper tests (`tools/tamper_test.py`): every component of the stateful and stateless witnesses was modified
  (pk, key index, message, r, counter, first/last chain element, each auth path, FORS sk/path, XMSS counters,
  signature elements and paths, stateless root) — all rejected.
* Both compilers give the same CMR for `shrincs_opt.simf`
  (`21713feaae63e718d10a409feed27a71e4ae7d74777bb9a389135a6cc8cfa6fa`).

### Toolchain note

The `simfony` binary bundled in the repo is SimplicityHL 31783fe built against rust-simplicity 7654c80 (0.6/0.7
era). That rust-simplicity has a pruning bug (fixed in simplicity-lang 0.7.1,
BlockstreamResearch/rust-simplicity#362): for some inputs the pruned program takes a branch that was pruned
("Execution reached a pruned branch") — it happens with the repo's own q=1 example and with q=2/q=207 here.
Witnesses built with that binary can be invalid on-chain. Use SimplicityHL ≥ 0.8.0 (simplicity-lang 0.9.0,
which also prunes with maximal sharing, #379) to produce the on-chain program.

## Reproducing

```
# compile + run + prune + measure one witness (the harness pulls SimplicityHL master from git)
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
* Dedicated tapleaves per range of q (q = 1 shown above; e.g. q ≤ 15 with `List<u128, 16>`).
