# simplicity-pq-signature
This repo contains hash-based signatures that can protect bitcoin against quantum computers

## Requirements
We use `#include` and `#define` directives so you may need to install `mcpp`:
```shell
brew install mcpp
```

## Signatures
`lamport.simf` - contains Lamport one-time signature implementation

`wots.simf` - contains Winternitz One Time Signature implementation

`sphincs/sphincs.simf` - contains SLH-DSA ([FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)) signature implementation (sphincs_verify only)

Each signature contains method `X_verify` (where X - signature name) that verifies the validity of the signature for the corresponding message hash and public key

## Running tests
`make test` - running all tests

`make example` - running example_main that verify one-time Lamport signature

## Usage
To execute this code import required signature file using `#include` directive (see [example](./example_main.simf)) and then run:
```bash
mkdir -p target
mcpp -P -I . your-file.simf -o target/your-file.simf
```

To run preprocessed file, run:
```bash
./simfony run --witness your-witness.wit target/your-file.simf
```

> [!IMPORTANT]
> `./simfony` - binary file that works for newest simplicityHL version. Now, [simfony-cli](https://github.com/starkware-bitcoin/stark-symphony/tree/master/simfony-cli) can't be used to run this code. Until they fix the Simfony version, use this instead
