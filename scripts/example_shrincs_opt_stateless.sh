mkdir -p target

chmod +x ./simfony

mcpp -P -I . optimized/shrincs_opt.simf -o target/shrincs_opt.simf
./simfony run --witness optimized/examples/stateless.wit target/shrincs_opt.simf
