use simplicityhl::{Arguments, CompiledProgram, WitnessValues};
use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::simplicity::{self, dag::DagLike};
use std::collections::BTreeMap;
use std::sync::Arc;

fn jet_histogram(node: &Arc<simplicity::RedeemNode>) -> BTreeMap<String, usize> {
    let mut hist = BTreeMap::new();
    for n in node.as_ref().post_order_iter::<simplicity::dag::NoSharing>() {
        if let simplicity::node::Inner::Jet(j) = n.node.inner() {
            *hist.entry(format!("{}", j)).or_insert(0usize) += 1;
        }
    }
    hist
}

fn report(label: &str, redeem: &Arc<simplicity::RedeemNode>) {
    let (prog, wit) = redeem.to_vec_with_witness();
    let b = redeem.bounds();
    println!("== {label} ==");
    println!("program bytes     : {}", prog.len());
    println!("witness bytes     : {}", wit.len());
    println!("cost (milliWU)    : {}", b.cost);
    println!("extra_cells (bits): {}", b.extra_cells);
    println!("nodes (no sharing): {}", redeem.as_ref().post_order_iter::<simplicity::dag::NoSharing>().count());
    println!("nodes (max shared): {}", redeem.as_ref().post_order_iter::<simplicity::dag::InternalSharing>().count());
    let hist = jet_histogram(redeem);
    let mut v: Vec<_> = hist.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    println!("jets (occurrences in tree, no sharing):");
    for (j, c) in v.iter().take(30) {
        println!("  {c:6}  {j}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog_text = std::fs::read_to_string(&args[1]).unwrap();
    let wit_text = std::fs::read_to_string(&args[2]).unwrap();
    let compiled = CompiledProgram::new(prog_text, Arguments::default(), false, Box::new(ElementsJetHinter::new()))
        .unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(1) });
    let witness: WitnessValues = serde_json::from_str(&wit_text).unwrap();

    let commit = compiled.commit();
    println!("commit-time program bytes (no witness): {}", commit.encode_to_vec().len());
    println!("CMR: {}", commit.cmr());

    let satisfied = compiled.satisfy(witness.clone()).unwrap();
    report("unpruned", satisfied.redeem());

    let env = simplicityhl::dummy_env::dummy();
    // run unpruned
    {
        let mut mac = simplicity::BitMachine::for_program(satisfied.redeem()).unwrap();
        match mac.exec(satisfied.redeem(), &env) {
            Ok(_) => println!("unpruned execution: OK"),
            Err(e) => println!("unpruned execution: ERROR {e}"),
        }
    }
    let pruned = compiled.satisfy_with_env(witness, Some(&env)).unwrap();
    report("pruned", pruned.redeem());
    composition(pruned.redeem());
    cost_attribution(pruned.redeem());
    size_breakdown(pruned.redeem());
    let mut mac = simplicity::BitMachine::for_program(pruned.redeem()).unwrap();
    match mac.exec(pruned.redeem(), &env) {
        Ok(_) => println!("pruned execution: OK"),
        Err(e) => println!("pruned execution: ERROR {e}"),
    }
    if args.len() > 3 {
        let (p, w) = pruned.redeem().to_vec_with_witness();
        std::fs::write(format!("{}.prog", &args[3]), &p).unwrap();
        std::fs::write(format!("{}.wit", &args[3]), &w).unwrap();
        println!("wrote {}.prog / {}.wit", &args[3], &args[3]);
    }
}

#[allow(dead_code)]
pub fn composition(redeem: &Arc<simplicity::RedeemNode>) {
    use simplicity::node::Inner;
    let mut kinds: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut const_bits = 0usize;
    let mut hidden = 0usize;
    let mut witness_bits = 0usize;
    for n in redeem.as_ref().post_order_iter::<simplicity::dag::InternalSharing>() {
        let k = match n.node.inner() {
            Inner::Iden => "iden", Inner::Unit => "unit", Inner::InjL(_) => "injl", Inner::InjR(_) => "injr",
            Inner::Take(_) => "take", Inner::Drop(_) => "drop", Inner::Comp(..) => "comp", Inner::Case(..) => "case",
            Inner::AssertL(..) => { hidden += 1; "assertl" }, Inner::AssertR(..) => { hidden += 1; "assertr" },
            Inner::Pair(..) => "pair", Inner::Disconnect(..) => "disconnect",
            Inner::Witness(_) => { witness_bits += n.node.arrow().target.bit_width(); "witness" },
            Inner::Fail(_) => "fail", Inner::Jet(_) => "jet",
            Inner::Word(w) => { const_bits += w.len(); "word" },
        };
        *kinds.entry(k).or_insert(0) += 1;
    }
    println!("composition (max sharing): {:?}", kinds);
    println!("const word bits: {} (= {} bytes), hidden-node refs: {} (= {} bytes), witness bits: {} (= {} bytes)",
        const_bits, const_bits / 8, hidden, hidden * 32, witness_bits, (witness_bits + 7) / 8);
}

#[allow(dead_code)]
pub fn cost_attribution(redeem: &Arc<simplicity::RedeemNode>) {
    use simplicity::node::Inner;
    use simplicity::jet::Jet;
    let mut overhead = 0u64; let mut comp_mid = 0u64; let mut iden_bits = 0u64; let mut wit_bits = 0u64;
    let mut word_bits = 0u64; let mut jet_cost = 0u64; let mut n_comp = 0u64; let mut n_iden = 0u64; let mut n_td = 0u64; let mut n_pair = 0u64;
    let mut comp_hist: BTreeMap<usize, (u64, u64)> = BTreeMap::new(); // mid width -> (count, bits)
    for n in redeem.as_ref().post_order_iter::<simplicity::dag::NoSharing>() {
        overhead += 100;
        match n.node.inner() {
            Inner::Iden => { n_iden += 1; iden_bits += n.node.arrow().target.bit_width() as u64; }
            Inner::Comp(l, _) => { n_comp += 1; let w = l.arrow().target.bit_width(); comp_mid += w as u64; let e = comp_hist.entry(w).or_insert((0,0)); e.0 += 1; e.1 += w as u64; }
            Inner::Witness(_) => { wit_bits += n.node.arrow().target.bit_width() as u64; }
            Inner::Word(w) => { word_bits += w.len() as u64; }
            Inner::Jet(j) => { jet_cost += format!("{}", j.cost()).parse::<u64>().unwrap_or(0); }
            Inner::Take(_) | Inner::Drop(_) => { n_td += 1; }
            Inner::Pair(..) => { n_pair += 1; }
            _ => {}
        }
    }
    let total = overhead + comp_mid + iden_bits + wit_bits + word_bits + jet_cost;
    println!("cost attribution (tree sum, mWU): total≈{total}");
    println!("  overhead 100/node : {overhead:>10}  ({} nodes: {} comp, {} iden, {} take/drop, {} pair)", overhead/100, n_comp, n_iden, n_td, n_pair);
    println!("  comp mid-type bits: {comp_mid:>10}");
    println!("  iden copy bits    : {iden_bits:>10}");
    println!("  witness bits      : {wit_bits:>10}");
    println!("  const word bits   : {word_bits:>10}");
    println!("  jet costs         : {jet_cost:>10}");
    let mut v: Vec<_> = comp_hist.into_iter().collect();
    v.sort_by(|a, b| b.1.1.cmp(&a.1.1));
    println!("  top comp mid widths (width: count, bits):");
    for (w, (c, b)) in v.iter().take(12) { println!("    {w:>6}: {c:>6} x -> {b:>9}"); }
}

#[allow(dead_code)]
pub fn size_breakdown(redeem: &Arc<simplicity::RedeemNode>) {
    // Rough per-kind encoded-size estimate: count nodes by kind with max sharing (what gets encoded).
    use simplicity::node::Inner;
    let mut jets: BTreeMap<String, usize> = BTreeMap::new();
    let mut words: Vec<usize> = vec![];
    for n in redeem.as_ref().post_order_iter::<simplicity::dag::InternalSharing>() {
        match n.node.inner() {
            Inner::Jet(j) => { *jets.entry(format!("{}", j)).or_insert(0) += 1; }
            Inner::Word(w) => { words.push(w.len()); }
            _ => {}
        }
    }
    println!("distinct jets: {:?}", jets);
    words.sort();
    println!("word sizes (bits): {:?}", words);
}
