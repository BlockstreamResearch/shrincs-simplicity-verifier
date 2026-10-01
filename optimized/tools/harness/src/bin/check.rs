// check: compile a SimplicityHL program, satisfy it with a witness file, run it (unpruned), prune, run pruned.
// Prints one JSON line. Never panics on verification failure.
use simplicityhl::{Arguments, CompiledProgram, WitnessValues};
use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::simplicity;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog_text = std::fs::read_to_string(&args[1]).unwrap();
    let wit_text = std::fs::read_to_string(&args[2]).unwrap();
    let compiled = match CompiledProgram::new(prog_text, Arguments::default(), false, Box::new(ElementsJetHinter::new())) {
        Ok(c) => c,
        Err(e) => { println!("{{\"ok\":false,\"stage\":\"compile\",\"error\":{:?}}}", e.to_string()); return; }
    };
    let witness: WitnessValues = match serde_json::from_str(&wit_text) {
        Ok(w) => w,
        Err(e) => { println!("{{\"ok\":false,\"stage\":\"witness-parse\",\"error\":{:?}}}", e.to_string()); return; }
    };
    let satisfied = match compiled.satisfy(witness.clone()) {
        Ok(s) => s,
        Err(e) => { println!("{{\"ok\":false,\"stage\":\"satisfy\",\"error\":{:?}}}", e.to_string()); return; }
    };
    let env = simplicityhl::dummy_env::dummy();
    let mut mac = simplicity::BitMachine::for_program(satisfied.redeem()).unwrap();
    if let Err(e) = mac.exec(satisfied.redeem(), &env) {
        println!("{{\"ok\":false,\"stage\":\"exec\",\"error\":{:?}}}", e.to_string());
        return;
    }
    let pruned = match compiled.satisfy_with_env(witness, Some(&env)) {
        Ok(p) => p,
        Err(e) => { println!("{{\"ok\":false,\"stage\":\"prune\",\"error\":{:?}}}", e.to_string()); return; }
    };
    let mut mac2 = simplicity::BitMachine::for_program(pruned.redeem()).unwrap();
    if let Err(e) = mac2.exec(pruned.redeem(), &env) {
        println!("{{\"ok\":false,\"stage\":\"exec-pruned\",\"error\":{:?}}}", e.to_string());
        return;
    }
    let (p, w) = pruned.redeem().to_vec_with_witness();
    let b = pruned.redeem().bounds();
    println!("{{\"ok\":true,\"cost\":{},\"program_bytes\":{},\"witness_bytes\":{},\"cmr\":\"{}\"}}", b.cost, p.len(), w.len(), compiled.commit().cmr());
}
