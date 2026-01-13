mkdir -p target

chmod +x ./simfony

mcpp -P -I . examples/lamport/lamport_main.simf -o target/lamport_main.simf
./simfony run --witness examples/lamport/lamport_main.wit target/lamport_main.simf