<h1 align="center">HELM <a href="https://github.com/jimouris/helm/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a> </h1>

<h2 align="center">HELM: Navigating Homomorphic Evaluation through Gates and Lookups</h2>


## Overview
HELM is a framework for evaluating synthesizable HDL designs in the encrypted
domain that is designed for multi-core CPU evaluation. Users can choose between
evaluating circuits composed of standard Boolean gates, low-precision LUTs, or
high-precision arithmetic operations.
In all cases, both sequential and combinational circuits are supported with the
exception of arithmetic circuits (which only support combinational logic).

## Build & Run

### 1) Clone, build, and run the tests:
```shell
git clone --recurse-submodules git@github.com:TrustworthyComputing/helm.git
cd helm
cargo build --release
cargo test --release
```

### 2) HELM Command Line Arguments
```shell
  -v, --verilog <FILE>              Verilog input file to evaluate
  -w, --input-wires <STRING> <HEX>  Input wire values (-w wire1 hex1 -w wire2 hex2 ...)
  -i, --input-wires-file <FILE>     CSV file that contains the input wire values (wire, value)
  -o, --output-wires-file <FILE>    CSV file to write the output wires (wire, value)
  -c, --cycles <NUMBER>             Number of cycles for sequential circuits [default: 1]
  -a, --arithmetic <TYPE>           Precision for arithmetic mode [possible values: u8, u16, u32, u64, u128]
  -p, --verbose                     Turn verbose printing on
  -h, --help                        Print help
```

### 3) HELM Modes of Operation

HELM has three modes: "gates"-mode, "LUTs"-mode, and "Arithmetic"-mode. HELM
automatically distinguishes between LUTs and gates circuit depending on the
cells utilized in the structural Verilog.
Below are two examples:


#### 3.1) Gates/Boolean Mode
Example in "gates"-mode:
```shell
cargo run --bin helm --release -- \
    --verilog ./hdl-benchmarks/processed-netlists/s27.v
cargo run --bin helm --release -- \
    --verilog ./hdl-benchmarks/processed-netlists/2-bit-adder.v \
    --input-wires-file ./hdl-benchmarks/test-cases/2-bit-adder.inputs.csv
```

You can also pass the input wire values as:
```shell
cargo run --bin helm --release -- \
    --verilog ./hdl-benchmarks/processed-netlists/2-bit-adder.v \
    -w a[0] 1 -w a[1] 0 -w b[0] 0 -w b[1] 1 -w cin 0
```

Or equivalently as `wire_name hex_value wire_width`
```shell
cargo run --bin helm --release -- \
    --verilog ./hdl-benchmarks/processed-netlists/2-bit-adder.v \
    -w a 1 2 -w b[0] 0 -w b[1] 1 -w cin 0
```
The above expands `a` to `a[0] = 1` and `a[1] = 1`.

Similarly:
```shell
cargo run --bin helm --release -- \
    --verilog ./hdl-benchmarks/processed-netlists/2-bit-adder.v \
    -w a 1 2 -w b 2 2 -w cin 0
```

#### 3.2) Lookup Tables (LUT) Mode
Example in "LUTs"-mode:
```shell
cargo run --bin helm --release -- \
    --verilog ./hdl-benchmarks/processed-netlists/8-bit-adder-lut-3-1.v \
    --input-wires-file hdl-benchmarks/test-cases/8-bit-adder.inputs.csv
```


#### 3.3) Arithmetic Mode
Example of an Arithmetic circuit.
This mode operates directly on behavioral Verilog files that include only
arithmetic operations. There is no need to invoke Yosys to perform any logic
synthesis.

```shell
cargo run --bin preprocessor --release  \
    --manifest-path=./hdl-benchmarks/Cargo.toml --  \
    --input ./hdl-benchmarks/designs/chi_squared.v \
    --output ./hdl-benchmarks/processed-netlists/chi_squared_arith.v \
    --arithmetic
cargo run --bin helm --release -- --arithmetic u32 \
    --verilog ./hdl-benchmarks/processed-netlists/chi_squared_arith.v \
    --input-wires-file ./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv
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
cargo run --bin helm --release -- --verilog ./hdl-benchmarks/processed-netlists/c880.v
```

<p align="center">
    <img src="./logos/twc.png" height="20%" width="20%">
</p>
<h4 align="center">Trustworthy Computing Group</h4>
