mkdir -p target

chmod +x ./simfony

mcpp -P -I . test.simf -o target/test.simf
./simfony run target/test.simf