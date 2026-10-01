# SHRINCS Simplicity Verifier
This repo contains hash-based signatures that can protect Bitcoin against quantum computers

> *⚠️ This project is a work in progress and is provided as-is for research, learning, and experimentation. It is not production-ready and has not undergone a formal security audit, code review, or verification process. This library may be incorrect, incomplete, or insecure.*

## 🛠 Requirements
We use `#include` and `#define` directives, so you may need to install `mcpp`:
```shell
brew install mcpp
```

> [!IMPORTANT]
> Currently, this project requires the bundled `./simfony` binary due to upstream incompatibilities in simfony-cli. This will be updated once the upstream issues are resolved.

## 🔐 Signatures
| Signature Scheme | File Path | Description |
| :--- | :--- | :--- |
| **Lamport** | `lamport.simf` | Lamport one-time signature implementation. |
| **WOTS** | `wots.simf` | Winternitz One-Time Signature implementation. |
| **SHRINCS** | `shrincs/shrincs.simf` | SHRINCS implementation. [C++](https://github.com/BlockstreamResearch/shrincs-cpp/tree/main). [📖 Read docs](./docs/shrincs_spec/main.pdf) |

> **Note:** Each signature contains method `X_verify` (where `X` is the scheme name) that verifies the validity of the signature for the corresponding message hash and public key

## 🧪 Running tests
* `make test` - runs all tests

* `make lamport_example` - runs Lamport verification example

* `make shrincs_example MODE={stateful|stateless}` - runs SHRINCS verification example
    * *Use `MODE=stateful` for XMSS-based stateful trees or `MODE=stateless` for SPHINCS-like stateless verification.*

## ⚡ Optimized verifier
[`optimized/shrincs_opt.simf`](./optimized/shrincs_opt.simf) is a reimplementation of `shrincs_verify` with the same hash layouts, written for the Simplicity cost model (split witnesses, no wide environments, streamed leaf hash, lean path steps). For the first stateful signature it needs no CPU-budget padding at all: 1797 B program + 1162 B witness, cost bound 2.73 M mWU, ≈ 933 vB per Liquid transaction. See [`optimized/README.md`](./optimized/README.md) for the full comparison, the witness layout, converters, test vectors and the measurement harness.

* `make shrincs_opt_example MODE={stateful|stateless}` - runs the optimized verifier on the converted example witnesses

## 🚀 Usage
To execute this code, import the required signature file using `#include` directive and then run:
```bash
mkdir -p target
mcpp -P -I . your-file.simf -o target/your-file.simf
```

To run the preprocessed file, run:
```bash
./simfony run --witness your-witness.wit target/your-file.simf
```

## 💻 Code example
```rust
#include "./shrincs/shrincs.simf"

fn main() {
    let message: u256 = ...;
    let pk: (u128, u128) = ...;
    let signature: Either<UXMSSSignature, SPHINCSSignature> = ...;
    let known_pk_part: u128 = ...;

    shrincs_verify((message, pk, signature, known_pk_part));
}
```

> 🧩 **Type Definitions:** Wondering how `UXMSSSignature` or `SPHINCSSignature` are structured under the hood? Check out the full type definitions in [`types.simf`](./types.simf).

> 📂 **More Examples:** For complete, runnable code including witness data setup, explore the [`examples/`](./examples) directory.
