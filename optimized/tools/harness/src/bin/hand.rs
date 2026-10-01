// hand: harness for hand-written Simplicity programs (rust-simplicity human-readable encoding).
//
//   hand <program.simpl> <witness.json>              parse, bind witnesses, prune against the dummy Elements env,
//                                                    execute, print one JSON line {ok, cost, program_bytes, witness_bytes, cmr}
//   hand <program.simpl> <witness.json> --nodes      also print node-kind counts / hidden CMRs / constant bits (stderr)
//   hand <program.simpl> <witness.json> --attr       per-definition unpruned cost bounds (type variables not fixed by the
//                                                    definition itself default to 1, so these are lower bounds)
//   hand <program.simpl> <witness.json> --roundtrip  decode the serialised (program, witness) bytes as a node would and
//                                                    re-run them
//   hand <program.simpl> <witness.json> <out.bin>    write the serialised program
//
// `cost` is the bound a node computes after decoding the serialised program (the consensus value); it can be a few
// hundred mWU below the bound of the DAG before serialisation because pruned witness types shrink. Never panics on a
// failed verification: the JSON line carries the stage and the error.
//
// Witness spec JSON: {"name": VALUE, ...} where VALUE is one of
//   {"w": "<hex>"}                      word of 4*len(hex) bits (power of two)
//   {"p": [VALUE, VALUE]}               product
//   {"none": TYPE}                      left injection of unit into 1 + TYPE
//   {"some": VALUE}                     right injection into 1 + ty(VALUE)
//   TYPE: {"w": bits} | {"p": [TYPE, TYPE]} | {"opt": TYPE}
// Names bind to the `witness` definitions of the program; names the program does not use are ignored.
use simplicityhl::simplicity;
use simplicity::human_encoding::Forest;
use simplicity::jet::Elements;
use simplicity::types::{self, Final};
use simplicity::{BitMachine, Value};
use std::collections::HashMap;
use std::sync::Arc;

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn word(hex: &str) -> Value {
    let bits = hex.len() * 4;
    assert!(bits.is_power_of_two(), "word width must be a power of two: {} bits", bits);
    if bits < 8 {
        let v = u8::from_str_radix(hex, 16).unwrap();
        return match bits {
            1 => Value::u1(v),
            2 => Value::u2(v),
            4 => Value::u4(v),
            _ => unreachable!(),
        };
    }
    let bytes = hex_to_bytes(hex);
    let mut vals: std::collections::VecDeque<Value> = bytes.into_iter().map(Value::u8).collect();
    while vals.len() > 1 {
        let mut next = std::collections::VecDeque::new();
        while let (Some(a), Some(b)) = (vals.pop_front(), vals.pop_front()) {
            next.push_back(Value::product(a, b));
        }
        vals = next;
    }
    vals.pop_front().unwrap()
}

fn ty(spec: &serde_json::Value) -> Arc<Final> {
    let o = spec.as_object().unwrap();
    if let Some(b) = o.get("w") {
        let bits = b.as_u64().unwrap() as usize;
        Final::two_two_n(bits.trailing_zeros() as usize).unwrap()
    } else if let Some(p) = o.get("p") {
        Final::product(ty(&p[0]), ty(&p[1]))
    } else if let Some(t) = o.get("opt") {
        Final::sum(Final::unit(), ty(t))
    } else {
        panic!("bad type spec {}", spec)
    }
}

fn value(spec: &serde_json::Value) -> Value {
    let o = spec.as_object().unwrap();
    if let Some(h) = o.get("w") {
        word(h.as_str().unwrap())
    } else if let Some(p) = o.get("p") {
        Value::product(value(&p[0]), value(&p[1]))
    } else if let Some(t) = o.get("none") {
        Value::none(ty(t))
    } else if let Some(v) = o.get("some") {
        Value::some(value(v))
    } else {
        panic!("bad value spec {}", spec)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = std::fs::read_to_string(&args[1]).unwrap();
    let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
    let mut witness: HashMap<Arc<str>, Value> = HashMap::new();
    for (k, v) in spec.as_object().unwrap() {
        witness.insert(Arc::from(k.as_str()), value(v));
    }
    let env = simplicityhl::dummy_env::dummy();
    types::Context::with_context(|ctx| {
        let forest = match Forest::parse::<Elements>(&prog) {
            Ok(f) => f,
            Err(e) => {
                println!("{{\"ok\":false,\"stage\":\"parse\",\"error\":{:?}}}", e.to_string());
                return;
            }
        };
        if args.len() > 3 && args[3] == "--attr" {
            // per-definition unpruned cost bounds (case = max of branches, witnesses populated)
            use simplicity::dag::{DagLike, InternalSharing};
            let main = forest.roots().get("main").expect("no main");
            let auto = ["id", "ut", "jl", "jr", "dp", "tk", "cp", "cs", "asstl", "asstr", "pr", "disc", "wit", "FAIL", "jt", "const"];
            let is_auto = |n: &str| auto.iter().any(|p| n.starts_with(p) && n[p.len()..].chars().all(|c| c.is_ascii_digit()) && n.len() > p.len());
            let mut rows = vec![];
            for data in main.as_ref().post_order_iter::<InternalSharing>() {
                let name = data.node.name().to_string();
                if is_auto(&name) {
                    continue;
                }
                let n = data.node.to_construct_node(&ctx, &witness, forest.roots());
                match n.finalize_unpruned() {
                    Ok(r) => {
                        let (p, _) = r.to_vec_with_witness();
                        rows.push((r.bounds().cost.to_string().parse::<u64>().unwrap_or(0), name, format!("{}", r.arrow()), p.len()))
                    }
                    Err(e) => rows.push((0, name, format!("ERR {}", e), 0)),
                }
            }
            rows.sort();
            for (c, n, a, p) in rows {
                println!("{:>10} {:>6} {:24} {}", c, p, n, a);
            }
            return;
        }
        let node = forest.to_witness_node(&ctx, &witness).expect("no main");
        let program = match node.finalize_pruned(&env) {
            Ok(p) => p,
            Err(e) => {
                println!("{{\"ok\":false,\"stage\":\"finalize\",\"error\":{:?}}}", e.to_string());
                return;
            }
        };
        let mut mac = match BitMachine::for_program(&program) {
            Ok(m) => m,
            Err(e) => {
                println!("{{\"ok\":false,\"stage\":\"machine\",\"error\":{:?}}}", e.to_string());
                return;
            }
        };
        if let Err(e) = mac.exec(&program, &env) {
            println!("{{\"ok\":false,\"stage\":\"exec\",\"error\":{:?}}}", e.to_string());
            return;
        }
        let (p, w) = program.to_vec_with_witness();
        let b = program.bounds();
        // The consensus cost is what a node computes after decoding the serialised program (type inference on the
        // pruned DAG can shrink pruned witness types), so always decode and report that cost too.
        use simplicity::{BitIter, RedeemNode};
        let decoded = RedeemNode::decode::<_, _, Elements>(BitIter::from(p.iter().cloned()), BitIter::from(w.iter().cloned())).expect("decode");
        assert_eq!(decoded.cmr(), program.cmr(), "CMR mismatch after round trip");
        let cost_decoded = decoded.bounds().cost.to_string().parse::<u64>().unwrap();
        if args.len() > 3 && args[3] == "--nodes" {
            use simplicity::dag::{DagLike, MaxSharing};
            use simplicity::node::Inner;
            let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
            let mut word_bits = 0usize;
            let mut hidden = 0usize;
            let mut total = 0usize;
            for data in program.as_ref().post_order_iter::<MaxSharing<_>>() {
                total += 1;
                let k = match data.node.inner() {
                    Inner::Iden => "iden", Inner::Unit => "unit", Inner::InjL(_) => "injl", Inner::InjR(_) => "injr",
                    Inner::Take(_) => "take", Inner::Drop(_) => "drop", Inner::Comp(..) => "comp", Inner::Case(..) => "case",
                    Inner::AssertL(..) => { hidden += 1; "assertl" }, Inner::AssertR(..) => { hidden += 1; "assertr" },
                    Inner::Pair(..) => "pair", Inner::Disconnect(..) => "disconnect", Inner::Witness(_) => "witness",
                    Inner::Fail(_) => "fail", Inner::Jet(_) => "jet", Inner::Word(w) => { word_bits += w.len(); "word" },
                };
                *counts.entry(k).or_default() += 1;
            }
            eprintln!("nodes={} hidden_cmrs={} word_bits={} ({} bytes) counts={:?}", total, hidden, word_bits, word_bits / 8, counts);
        }
        println!(
            "{{\"ok\":true,\"cost\":{},\"cost_pre_decode\":{},\"program_bytes\":{},\"witness_bytes\":{},\"cmr\":\"{}\"}}",
            cost_decoded,
            b.cost,
            p.len(),
            w.len(),
            program.cmr()
        );
        if args.len() > 3 && args[3] == "--roundtrip" {
            // re-run the decoded program
            let mut mac = BitMachine::for_program(&decoded).unwrap();
            mac.exec(&decoded, &env).expect("decoded program failed");
            eprintln!("roundtrip ok: decoded {} program bytes + {} witness bytes, same CMR, executes; cost before/after decode {} / {}", p.len(), w.len(), b.cost, cost_decoded);
        } else if args.len() > 3 {
            std::fs::write(&args[3], p).unwrap();
        }
    });
}
