mkdir -p target

chmod +x ./simfony

mcpp -P -I . examples/shrincs/shrincs_main.simf -o target/shrincs_main.simf
./simfony run --witness examples/shrincs/shrincs_main_stateless.wit target/shrincs_main.simf