#!/bin/bash
# Full validation of the hand-written verifiers:
#   1. the Python references accept all 207 stateful and all 43 stateless vectors
#   2. the general program (key indices 1..206) and the index-207 program accept their vectors
#   3. every per-index program accepts its vector (cold, hot-pad and hot-pad+nested variants)
#   4. the stateless program (both checksum variants) accepts all 43 stateless vectors
#   5. tampered witnesses are rejected (stateful: general q=1/10/206, fixed q=1/10/207; stateless: two vectors)
#   6. serialised program + witness bytes decode and execute (round trip)
# Needs: python3, the harness built (cd ../tools/harness && cargo build --release --bin hand).
set -e
cd "$(dirname "$0")"
H=${HAND_BIN:-../tools/harness/target/release/hand}
VEC=${VECTORS:-../vectors/vectors_full.jsonl}
VEC_SL=${VECTORS_SL:-../vectors/vectors_stateless.jsonl}
python3 ref_verify.py $VEC
python3 ref_verify_sl.py $VEC
python3 ref_verify_sl.py $VEC_SL
python3 make_witness.py $VEC witnesses_all > /dev/null
mkdir -p programs_all
python3 gen_stateful_dag.py programs_all/general.simpl --no-last > /dev/null
python3 gen_stateful_dag.py programs_all/layout1_q207.simpl --fixed-q=207 --hot-pad --nested-chain > /dev/null
ok=0; bad=0
for q in $(seq 1 206); do
  if $H programs_all/general.simpl witnesses_all/stateful_q$q.hand.json | grep -q '"ok":true'; then ok=$((ok+1)); else bad=$((bad+1)); echo "general q=$q FAILED"; fi
done
if $H programs_all/layout1_q207.simpl witnesses_all/stateful_q207.hand.json | grep -q "\"ok\":true"; then ok=$((ok+1)); else bad=$((bad+1)); echo "q207 FAILED"; fi
echo "layout 1 (general + q207): $ok ok, $bad failed"
ok=0; bad=0
for q in $(seq 1 207); do
  for fl in "" "--hot-pad" "--hot-pad --nested-chain"; do
    suf=""; [ "$fl" = "--hot-pad" ] && suf="_hotpad"; [ "$fl" = "--hot-pad --nested-chain" ] && suf="_hotpad_nested"
    python3 gen_stateful_dag.py programs_all/stateful_q$q$suf.simpl --fixed-q=$q $fl > /dev/null
    if $H programs_all/stateful_q$q$suf.simpl witnesses_all/stateful_q$q.hand.json | grep -q '"ok":true'; then ok=$((ok+1)); else bad=$((bad+1)); echo "fixed q=$q $fl FAILED"; fi
  done
done
echo "layout 2 (per-index programs, cold / hot-pad / hot-pad+nested): $ok ok, $bad failed"
python3 make_witness_sl.py $VEC witnesses_sl > /dev/null
python3 make_witness_sl.py $VEC_SL witnesses_sl_b > /dev/null
python3 gen_stateless_dag.py programs_all/stateless_sum4.simpl > /dev/null
python3 gen_stateless_dag.py programs_all/stateless_sum32.simpl --sum=32 > /dev/null
ok=0; bad=0
for prog in programs_all/stateless_sum4.simpl programs_all/stateless_sum32.simpl; do
  for f in witnesses_sl/*.hand.json witnesses_sl_b/*.hand.json; do
    if $H $prog $f | grep -q '"ok":true'; then ok=$((ok+1)); else bad=$((bad+1)); echo "stateless $prog $f FAILED"; fi
  done
done
echo "stateless programs (2 variants x 43 vectors): $ok ok, $bad failed"
for q in 1 10 206; do echo "tamper general q=$q: $(python3 tamper.py programs_all/general.simpl witnesses_all/stateful_q$q.hand.json | tail -1)"; done
for q in 1 10 207; do echo "tamper fixed q=$q: $(python3 tamper.py programs_all/stateful_q$q.simpl witnesses_all/stateful_q$q.hand.json fixed | tail -1)"; done
echo "tamper stateless (vector 0): $(python3 tamper_sl.py programs_all/stateless_sum4.simpl witnesses_sl/stateless_0.hand.json | tail -1)"
echo "tamper stateless (vector b7): $(python3 tamper_sl.py programs_all/stateless_sum32.simpl witnesses_sl_b/stateless_7.hand.json | tail -1)"
$H programs_all/general.simpl witnesses_all/stateful_q1.hand.json --roundtrip 2>&1 | grep roundtrip
$H programs_all/layout1_q207.simpl witnesses_all/stateful_q207.hand.json --roundtrip 2>&1 | grep roundtrip
$H programs_all/stateless_sum4.simpl witnesses_sl/stateless_0.hand.json --roundtrip 2>&1 | grep roundtrip
