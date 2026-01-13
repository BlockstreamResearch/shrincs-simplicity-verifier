mkdir -p target

chmod +x ./simfony

mcpp -P -I . examples/sphincs/sphincs_main.simf -o target/sphincs_main.simf
./simfony run --witness examples/sphincs/sphincs_main.wit target/sphincs_main.simf