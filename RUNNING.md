# HELM Experiments

## 1. Multipliers
1. **16-bit**
   1. **Gates**
     ```shell
     cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/16-bit-mult-gates.v \
        --output ./hdl-benchmarks/processed-netlists/16-bit-mult-gates.v
     cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/16-bit-mult-gates.v \
        --input-wires-file ./hdl-benchmarks/test-cases/16-bit-mult.inputs.csv
     ```
   2. **LUT w/ LBB**
     ```shell
     cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/16-bit-mult-lut-2-1.v \
        --output ./hdl-benchmarks/processed-netlists/16-bit-mult-lut-2-1.v
     cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/16-bit-mult-lut-2-1.v \
        --input-wires-file ./hdl-benchmarks/test-cases/16-bit-mult.inputs.csv
     ```
   3. **LUT w/o LBB**
     ```shell
     cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/designs/16-bit-mult.v \
        --output ./hdl-benchmarks/processed-netlists/16-bit-mult-arith.v \
        --arithmetic
     cargo run --bin helm --release -- --arithmetic u16 \
        --verilog ./hdl-benchmarks/processed-netlists/16-bit-mult-arith.v \
        -w G11 99 -w G12 4
     ```
2. Support for 32-bit, 64-bit, 128-bit.


## 2. Matrix Multiplication
1. **5x5 x 5x5**
   1. **Gates**
     ```shell
     cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/5x5_x_5x5_mmult_gates.v \
        --output ./hdl-benchmarks/processed-netlists/5x5_x_5x5_mmult_gates.v
     cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/5x5_x_5x5_mmult_gates.v
     ```
   2. **LUT w/ LBB**
     ```shell
     cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/5x5_x_5x5_mmult-lut-2-1.v \
        --output ./hdl-benchmarks/processed-netlists/5x5_x_5x5_mmult-lut-2-1.v
     cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/5x5_x_5x5_mmult-lut-2-1.v
     ```
   3. **LUT w/o LBB**
     ```shell
     cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/designs/5x5_x_5x5-mmult.v \
        --output ./hdl-benchmarks/processed-netlists/5x5_x_5x5-mmult-arith.v \
        --arithmetic
     cargo run --bin helm --release -- \
        --arithmetic u16 \
        --verilog ./hdl-benchmarks/processed-netlists/5x5_x_5x5-mmult-arith.v
     ```
2. Support for 10x10 x 10x10 and 15x15 x 15x15.


## 3. Chi squared
1. **Gates**
  ```shell
  cargo run --bin preprocessor --release \
     --manifest-path=./hdl-benchmarks/Cargo.toml -- \
     --input ./hdl-benchmarks/netlists/chi_squared_gates.v \
     --output ./hdl-benchmarks/processed-netlists/chi_squared_gates.v
  cargo run --bin helm --release -- \
     --verilog ./hdl-benchmarks/processed-netlists/chi_squared_gates.v \
     --input-wires-file ./hdl-benchmarks/test-cases/chi_squared_bin_1.inputs.csv
  ```
2. **LUT w/ LBB**
  ```shell
  cargo run --bin preprocessor --release \
     --manifest-path=./hdl-benchmarks/Cargo.toml -- \
     --input ./hdl-benchmarks/netlists/chi_squared-lut-2-1.v \
     --output ./hdl-benchmarks/processed-netlists/chi_squared-lut-2-1.v
  cargo run --bin helm --release -- \
     --verilog ./hdl-benchmarks/processed-netlists/chi_squared-lut-2-1.v \
     --input-wires-file ./hdl-benchmarks/test-cases/chi_squared_bin_1.inputs.csv
  ```
3. **LUT w/o LBB**
  ```shell
  cargo run --bin preprocessor --release \
     --manifest-path=./hdl-benchmarks/Cargo.toml -- \
     --input ./hdl-benchmarks/designs/chi_squared.v \
     --output ./hdl-benchmarks/processed-netlists/chi_squared_arith.v \
     --arithmetic
  cargo run --bin helm --release -- \
     --arithmetic u32 \
     --verilog ./hdl-benchmarks/processed-netlists/chi_squared_arith.v \
     --input-wires-file ./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv
  ```

## 4. Euclidean Distance
1. `n = 32` Gates
  ```shell
  cargo run --bin preprocessor --release \
      --manifest-path=./hdl-benchmarks/Cargo.toml -- \
      --input ./hdl-benchmarks/netlists/v32_euclidean_gates.v \
      --output ./hdl-benchmarks/processed-netlists/v32_euclidean_gates.v
  cargo run --bin helm --release -- \
      --verilog ./hdl-benchmarks/processed-netlists/v32_euclidean_gates.v
  ```
3. `n = 32` 2:1 LUT w/ LBB
  ```shell
  cargo run --bin preprocessor --release \
      --manifest-path=./hdl-benchmarks/Cargo.toml -- \
      --input ./hdl-benchmarks/netlists/v32_euclidean-lut-2-1.v \
      --output ./hdl-benchmarks/processed-netlists/v32_euclidean-lut-2-1.v
  cargo run --bin helm --release -- \
      --verilog ./hdl-benchmarks/processed-netlists/v32_euclidean-lut-2-1.v
  ```
4. `n = 32` LUT w/o LBB
  ```shell
  cargo run --bin preprocessor --release \
      --manifest-path=./hdl-benchmarks/Cargo.toml -- \
      --input ./hdl-benchmarks/designs/v32-euclidean-distance.v \
      --output ./hdl-benchmarks/processed-netlists/v32_euclidean-arith.v \
      --arithmetic
  cargo run --bin helm --release -- \
      --arithmetic u32 \
      --verilog ./hdl-benchmarks/processed-netlists/v32_euclidean-arith.v
  ```
5. Support for `n = 64`.


## 5. CRC-32
1. **Gates**
  ```shell
  cargo run --bin preprocessor --release \
      --manifest-path=./hdl-benchmarks/Cargo.toml -- \
      --input ./hdl-benchmarks/netlists/crc-32-gates.v \
      --output ./hdl-benchmarks/processed-netlists/crc-32-gates.v
  cargo run --bin helm --release -- \
      --verilog ./hdl-benchmarks/processed-netlists/crc-32-gates.v
  ```
2. **LUT w/ LBB**
  ```shell
  cargo run --bin preprocessor --release \
      --manifest-path=./hdl-benchmarks/Cargo.toml -- \
      --input ./hdl-benchmarks/netlists/crc32-lut-2-1.v \
      --output ./hdl-benchmarks/processed-netlists/crc32-lut-2-1.v
  cargo run --bin helm --release -- \
      --verilog ./hdl-benchmarks/processed-netlists/crc32-lut-2-1.v
  ```

## 6. AES
1. **AES Core**
   1. **Gates**
    ```shell
    cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/aes_core_gates.v \
        --output ./hdl-benchmarks/processed-netlists/aes_core_gates.v
    cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/aes_core_gates.v \
        --input-wires-file ./hdl-benchmarks/test-cases/aes.inputs.csv
    ```
   2. **LUT w/ LBB**
    ```shell
    cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/aes-core-lut-2-1.v \
        --output ./hdl-benchmarks/processed-netlists/aes-core-lut-2-1.v
    cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/aes-core-lut-2-1.v \
        --input-wires-file ./hdl-benchmarks/test-cases/aes.inputs.csv
    ```
2. Support for AES-128 with Key Scheduling and AES-128 without Key Scheduling.


## 7. Box Blur and Gaussian Blur
1. **Gaussian Blur**
   1. **Gates**
    ```shell
    cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/r45-c66-gaussian-blur-gates.v \
        --output ./hdl-benchmarks/processed-netlists/r45-c66-gaussian-blur-gates.v
    cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/r45-c66-gaussian-blur-gates.v
    ```
   2. **LUT w/ LBB**
    ```shell
    cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/netlists/r45-c66-gaussian-blur-lut-2-1.v \
        --output ./hdl-benchmarks/processed-netlists/r45-c66-gaussian-blur-lut-2-1.v
    cargo run --bin helm --release -- \
        --verilog ./hdl-benchmarks/processed-netlists/r45-c66-gaussian-blur-lut-2-1.v
    ```
   3. **LUT w/o LBB**
    ```shell
    cargo run --bin preprocessor --release \
        --manifest-path=./hdl-benchmarks/Cargo.toml -- \
        --input ./hdl-benchmarks/designs/r45_c66-blur.v \
        --output ./hdl-benchmarks/processed-netlists/r45-c66-gaussian-blur-arith.v \
        --arithmetic
    cargo run --bin helm --release -- \
        --arithmetic u8 \
        --verilog ./hdl-benchmarks/processed-netlists/r45-c66-gaussian-blur-arith.v \
        --input-wires-file ./hdl-benchmarks/test-cases/r45-c66-gaussian-blur.inputs.csv
    ```
2. Support for Gaussian Blur.


## 9. ISCAS'85
1.  **c1355**
    1.  **Gates**
     ```shell
     cargo run --bin preprocessor --release \
         --manifest-path=./hdl-benchmarks/Cargo.toml -- \
         --input ./hdl-benchmarks/netlists/c1355.v \
         --output ./hdl-benchmarks/processed-netlists/c1355.v
     cargo run --bin helm --release -- --verilog ./hdl-benchmarks/processed-netlists/c1355.v
     ```
    2. **LUT w/ LBB**
     ```shell
     cargo run --bin preprocessor --release \
         --manifest-path=./hdl-benchmarks/Cargo.toml -- \
         --input ./hdl-benchmarks/netlists/c1355-lut-2-1.v \
         --output ./hdl-benchmarks/processed-netlists/c1355-lut-2-1.v
     cargo run --bin helm --release -- --verilog ./hdl-benchmarks/processed-netlists/c1355-lut-2-1.v
     ```
2. Support for c1908, c2670, c3540, c5315, c6288, c7552.


## 10. ISCAS'89
1.  **s386**
    1.  **Gates**
     ```shell
     cargo run --bin preprocessor --release \
         --manifest-path=./hdl-benchmarks/Cargo.toml -- \
         --input ./hdl-benchmarks/netlists/s386.v \
         --output ./hdl-benchmarks/processed-netlists/s386.v
     cargo run --bin helm --release -- --verilog ./hdl-benchmarks/processed-netlists/s386.v --cycles 1
     ```
    2.  **LUT w/ LBB**
     ```shell
     cargo run --bin preprocessor --release \
         --manifest-path=./hdl-benchmarks/Cargo.toml -- \
         --input ./hdl-benchmarks/netlists/s386-lut-2-1.v \
         --output ./hdl-benchmarks/processed-netlists/s386-lut-2-1.v
     cargo run --bin helm --release -- --verilog ./hdl-benchmarks/processed-netlists/s386-lut-2-1.v --cycles 1
     ```
2. Support for s510, s1196, s5378, s9234, s13207, s15850.
