<h1 align="center">HELM <a href="https://github.com/jimouris/helm/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a> </h1>

<h2 align="center">HELM: Homomorphic Evaluation with Lookup table Memoization</h2>


## Overview
HELM is a framework for evaluating synthesizable HDL designs in the encrypted
domain that is designed for multi-core CPU evaluation. Users can choose between
evaluating circuits composed of standard Boolean gates or low-precision LUTs. In
either case, both sequential and combinational circuits are supported.

### Clone the repository
```shell
git clone --recurse-submodules git@github.com:TrustworthyComputing/helm.git
```

### Build & Run

Compile and run the tests:
```shell
cargo build --release
cargo test --release
```

HELM has two modes: "gates"-mode and "LUTs"-mode. HELM automatically detects if
a LUTs or a gates circuit has been provided as input. Below are two examples:

Example in "gates"-mode:
```shell
cargo run --bin helm --release -- \
    --input ./hdl-benchmarks/processed-netlists/s27.v
cargo run --bin helm --release -- \
    --input ./hdl-benchmarks/processed-netlists/2-bit-adder.v \
    --wires ./hdl-benchmarks/test-cases/2-bit-adder.inputs.csv
```

Example in "LUTs"-mode:
```shell
cargo run --bin helm --release -- \
    --input ./hdl-benchmarks/processed-netlists/8-bit-adder-lut-3-1.v \
    --wires hdl-benchmarks/test-cases/8-bit-adder.inputs.csv
```

### Example of an ISCAS'85 circuit
If a circuit is in the [netlists](./hdl-benchmarks/netlists/) directory but not
in the [processed-netlists](./hdl-benchmarks/processed-netlists/), run the
preprocessor and then helm as following:

```shell
cargo run --bin preprocessor --release  \
    --manifest-path=./hdl-benchmarks/Cargo.toml --  \
    --input ./hdl-benchmarks/netlists/c880.v \
    --output ./hdl-benchmarks/processed-netlists/c880.v
cargo run --bin helm --release -- --input ./hdl-benchmarks/processed-netlists/c880.v
```

### Example of an Arithmetic circuit
This mode operates directly on behavioral Verilog files that include only
arithmetic operations. There is no need to invoke Yosys to perform any logic
synthesis.

```shell
cargo run --bin preprocessor --release  \
    --manifest-path=./hdl-benchmarks/Cargo.toml --  \
    --input ./hdl-benchmarks/designs/chi_squared.v \
    --output ./hdl-benchmarks/processed-netlists/chi_squared_arith.v
cargo run --bin helm --release -- --arithmetic u32 --input ./hdl-benchmarks/processed-netlists/chi_squared_arith.v --wires ./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv
```

<p align="center">
    <img src="./logos/twc.png" height="20%" width="20%">
</p>
<h4 align="center">Trustworthy Computing Group</h4>
