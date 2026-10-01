test:
	bash scripts/test.sh
	bash scripts/example_shrincs_stateful.sh
	bash scripts/example_shrincs_stateless.sh

lamport_example:
	bash scripts/example_lamport.sh

MODE ?= stateful

shrincs_example:
	bash scripts/example_shrincs_$(MODE).sh

# Cost-model-optimized verifier (see optimized/README.md)
shrincs_opt_example:
	bash scripts/example_shrincs_opt_$(MODE).sh

hand_example:
	cd optimized/tools/harness && cargo build --release --bin hand
	optimized/tools/harness/target/release/hand optimized/hand/programs/general.simpl optimized/hand/witnesses/stateful_q1.hand.json --nodes
