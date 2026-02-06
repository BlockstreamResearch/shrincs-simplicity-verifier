test:
	bash scripts/test.sh

lamport_example:
	bash scripts/example_lamport.sh

MODE ?= stateful

shrincs_example:
	bash scripts/example_shrincs_$(MODE).sh