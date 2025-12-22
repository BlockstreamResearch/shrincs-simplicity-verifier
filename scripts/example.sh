mkdir -p target

chmod +x ./simfony

mcpp -P -I . example_main.simf -o target/example_main.simf
./simfony run --witness example_main.wit target/example_main.simf