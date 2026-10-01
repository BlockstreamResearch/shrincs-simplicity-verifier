mkdir -p target

chmod +x ./simfony

mcpp -P -I . optimized/shrincs_opt.simf -o target/shrincs_opt.simf
./simfony run --witness optimized/examples/stateful_q1.wit target/shrincs_opt.simf
