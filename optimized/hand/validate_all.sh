#!/bin/bash
# Full validation of the hand-written stateful verifier:
#   1. the Python reference accepts all 207 stateful vectors
#   2. the general program (key indices 1..206) and the index-207 program accept their vectors
#   3. every per-index program accepts its vector (cold and hot-pad variants)
#   4. tampered witnesses are rejected (general q=1/10/206, fixed q=1/10/207)
# Needs: python3, the harness built (cd ../tools/harness && cargo build --release --bin hand).
set -e
cd "$(dirname "$0")"
H=${HAND_BIN:-../tools/harness/target/release/hand}
VEC=${VECTORS:-../vectors/vectors_full.jsonl}
python3 ref_verify.py $VEC
python3 make_witness.py $VEC witnesses_all > /dev/null
mkdir -p programs_all
python3 gen_stateful_dag.py programs_all/general.simpl --no-last > /dev/null
python3 gen_stateful_dag.py programs_all/stateful_q207.simpl --fixed-q=207 --hot-pad > /dev/null
ok=0; bad=0
for q in $(seq 1 206); do
  if $H programs_all/general.simpl witnesses_all/stateful_q$q.hand.json | grep -q '"ok":true'; then ok=$((ok+1)); else bad=$((bad+1)); echo "general q=$q FAILED"; fi
done
if $H programs_all/stateful_q207.simpl witnesses_all/stateful_q207.hand.json | grep -q '"ok":true'; then ok=$((ok+1)); else bad=$((bad+1)); echo "q207 FAILED"; fi
echo "layout 1 (general + q207): $ok ok, $bad failed"
ok=0; bad=0
for q in $(seq 1 207); do
  for fl in "" "--hot-pad"; do
    suf=""; [ -n "$fl" ] && suf="_hot"
    python3 gen_stateful_dag.py programs_all/stateful_q$q$suf.simpl --fixed-q=$q $fl > /dev/null
    if $H programs_all/stateful_q$q$suf.simpl witnesses_all/stateful_q$q.hand.json | grep -q '"ok":true'; then ok=$((ok+1)); else bad=$((bad+1)); echo "fixed q=$q $fl FAILED"; fi
  done
done
echo "layout 2 (per-index programs, cold and hot-pad): $ok ok, $bad failed"
for q in 1 10 206; do echo "tamper general q=$q: $(python3 tamper.py programs_all/general.simpl witnesses_all/stateful_q$q.hand.json | tail -1)"; done
for q in 1 10 207; do echo "tamper fixed q=$q: $(python3 tamper.py programs_all/stateful_q$q.simpl witnesses_all/stateful_q$q.hand.json fixed | tail -1)"; done
$H programs_all/general.simpl witnesses_all/stateful_q1.hand.json --roundtrip 2>&1 | grep roundtrip
$H programs_all/stateful_q207.simpl witnesses_all/stateful_q207.hand.json --roundtrip 2>&1 | grep roundtrip
