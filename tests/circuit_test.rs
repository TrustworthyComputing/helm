#[cfg(feature = "gpu")]
use concrete_core::prelude::*;
use debug_print::debug_println;
#[cfg(feature = "gpu")]
use helm::circuit::CircuitCuda;
use helm::{
    circuit::{
        ArithCircuit, Circuit, EvalCircuit, GateCircuit, HighPrecisionLutCircuit, LutCircuit,
    },
    verilog_parser, PtxtType,
};
use itertools::Itertools;
use std::{collections::HashMap, vec};
use tfhe::{
    boolean::gen_keys,
    generate_keys,
    integer::{
        wopbs::WopbsKey as WopbsKeyInt, ClientKey as ClientKeyInt, ServerKey as ServerKeyInt,
    },
    shortint::{
        parameters::{
            parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_2_CARRY_1_KS_PBS,
        },
        wopbs::WopbsKey as WopbsKeyShortInt,
    },
    ConfigBuilder,
};

#[test]
fn two_bit_adder() {
    let (gates_set, wire_set, input_wires, _, _, _, _) =
        verilog_parser::read_verilog_file("hdl-benchmarks/processed-netlists/2-bit-adder.v", false);

    let empty = vec![];
    let mut circuit = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit.sort_circuit();
    assert_eq!(circuit.get_ordered_gates().len(), 10);
    circuit.compute_levels();

    let mut wire_map = HashMap::new();
    for wire in &wire_set {
        wire_map.insert(wire.to_string(), PtxtType::Bool(true));
    }
    for input_wire in &input_wires {
        wire_map.insert(input_wire.to_string(), PtxtType::Bool(true));
    }
    wire_map = circuit.evaluate(&wire_map);

    assert_eq!(wire_map.len(), 15);
    assert_eq!(input_wires.len(), 5);

    assert_eq!(wire_map["sum[0]"], PtxtType::Bool(true));
    assert_eq!(wire_map["sum[1]"], PtxtType::Bool(true));
    assert_eq!(wire_map["cout"], PtxtType::Bool(true));
    assert_eq!(wire_map["i0"], PtxtType::Bool(false));
    assert_eq!(wire_map["i1"], PtxtType::Bool(false));
}

#[test]
fn encrypted_two_bit_adder() {
    let datatype = "bool";
    let (gates_set, wire_set, input_wires, _, _, _, _) =
        verilog_parser::read_verilog_file("hdl-benchmarks/processed-netlists/2-bit-adder.v", false);

    let empty = vec![];
    let mut circuit = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit.sort_circuit();
    circuit.compute_levels();

    // Encrypted
    let (client_key, server_key) = gen_keys();

    // Plaintext
    let mut ptxt_wire_map = HashMap::new();
    for wire in &wire_set {
        ptxt_wire_map.insert(wire.to_string(), PtxtType::Bool(true));
    }
    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), PtxtType::Bool(true));
    }
    ptxt_wire_map = circuit.evaluate(&ptxt_wire_map);

    let mut enc_wire_map = HashMap::new();
    for wire in wire_set {
        enc_wire_map.insert(wire, client_key.encrypt(false));
    }
    for input_wire in &input_wires {
        enc_wire_map.insert(input_wire.to_string(), client_key.encrypt(true));
    }
    let mut circuit = GateCircuit::new(client_key.clone(), server_key, circuit);

    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt(&enc_wire_map[wire_name]),
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], PtxtType::Bool(dec_wire_map[key]));
    }
}

#[cfg(feature = "gpu")]
#[test]
fn encrypted_16_bit_multiplier_gpu() {
    let datatype = "bool";
    let (gates_set, wire_set, input_wires, output_wires, _, _, _) =
        verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/16-bit-mult-gates.v",
            false,
        );

    let empty = vec![];
    let mut circuit = Circuit::new(gates_set, &input_wires, &output_wires, &empty);
    circuit.sort_circuit();
    circuit.compute_levels();

    // Encrypted
    let (lwe_dim, glwe_dim, poly_size) = (
        LweDimension(512),
        GlweDimension(1),
        PolynomialSize(1024),
    );
    let stddev_glwe = 0.00000002980232238769531_f64;
    let noise = Variance(stddev_glwe.powf(2.0));
    let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    let (ks_lc, ks_bl) = (DecompositionLevelCount(8), DecompositionBaseLog(2));

    let unsafe_secret = 0_u128;
    let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(unsafe_secret))).unwrap();
    let mut parallel_engine =
        DefaultParallelEngine::new(Box::new(UnixSeeder::new(unsafe_secret))).unwrap();
    let cuda_engine = CudaEngine::new(()).unwrap();

    // Generate the keys
    let h_input_key = default_engine.generate_new_lwe_secret_key(lwe_dim).unwrap();
    let h_lut_key: GlweSecretKey32 = default_engine
        .generate_new_glwe_secret_key(glwe_dim, poly_size)
        .unwrap();
    let h_interm_sk = default_engine
        .transform_glwe_secret_key_to_lwe_secret_key(h_lut_key.clone())
        .unwrap();
    let h_keyswitch_key = default_engine
        .generate_new_lwe_keyswitch_key(&h_interm_sk, &h_input_key, ks_lc, ks_bl, noise)
        .unwrap();
    // create a BSK with multithreading
    let h_bootstrap_key = parallel_engine
        .generate_new_lwe_bootstrap_key(&h_input_key, &h_lut_key, dec_bl, dec_lc, noise)
        .unwrap();
    let d_fourier_bsk = cuda_engine
        .convert_lwe_bootstrap_key(&h_bootstrap_key)
        .unwrap();
    let d_fourier_ksk = cuda_engine
        .convert_lwe_keyswitch_key(&h_keyswitch_key)
        .unwrap();

    let input_wire_file: Option<String> =
        Some("./hdl-benchmarks/test-cases/32-bit-mult.inputs.csv".to_string());
    // Plaintext
    let input_wire_map = helm::get_input_wire_map(input_wire_file, vec![], "bool");

    let mut ptxt_wire_map = circuit.initialize_wire_map(&wire_set, &input_wire_map, datatype);

    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
    }
    ptxt_wire_map = circuit.evaluate(&ptxt_wire_map);

    let mut circuit = CircuitCuda::new(
        circuit,
        default_engine,
        cuda_engine,
        h_input_key,
        d_fourier_bsk,
        d_fourier_ksk,
        lwe_dim,
        noise,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);

    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let decrypted_outputs = EvalCircuit::decrypt_outputs(&mut circuit, &enc_wire_map, true);
    for key in decrypted_outputs.keys() {
        assert_eq!(ptxt_wire_map[key], decrypted_outputs[key]);
    }
    debug_println!("output wire map: {:?}", decrypted_outputs);
}

#[cfg(feature = "gpu")]
#[test]
fn encrypted_32_bit_multiplier_gpu() {
    let datatype = "bool";
    let (gates_set, wire_set, input_wires, output_wires, _, _, _) =
        verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/32-bit-mult-gates.v",
            false,
        );

    let empty = vec![];
    let mut circuit = Circuit::new(gates_set, &input_wires, &output_wires, &empty);
    circuit.sort_circuit();
    circuit.compute_levels();

    // Encrypted
    let (lwe_dim, glwe_dim, poly_size) = (
        LweDimension(512),
        GlweDimension(1),
        PolynomialSize(1024),
    );
    let stddev_glwe = 0.00000002980232238769531_f64;
    let noise = Variance(stddev_glwe.powf(2.0));
    let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    let (ks_lc, ks_bl) = (DecompositionLevelCount(8), DecompositionBaseLog(2));

    let unsafe_secret = 0_u128;
    let mut default_engine = DefaultEngine::new(Box::new(UnixSeeder::new(unsafe_secret))).unwrap();
    let mut parallel_engine =
        DefaultParallelEngine::new(Box::new(UnixSeeder::new(unsafe_secret))).unwrap();
    let cuda_engine = CudaEngine::new(()).unwrap();

    // Generate the keys
    let h_input_key = default_engine.generate_new_lwe_secret_key(lwe_dim).unwrap();
    let h_lut_key: GlweSecretKey32 = default_engine
        .generate_new_glwe_secret_key(glwe_dim, poly_size)
        .unwrap();
    let h_interm_sk = default_engine
        .transform_glwe_secret_key_to_lwe_secret_key(h_lut_key.clone())
        .unwrap();
    let h_keyswitch_key = default_engine
        .generate_new_lwe_keyswitch_key(&h_interm_sk, &h_input_key, ks_lc, ks_bl, noise)
        .unwrap();
    // create a BSK with multithreading
    let h_bootstrap_key = parallel_engine
        .generate_new_lwe_bootstrap_key(&h_input_key, &h_lut_key, dec_bl, dec_lc, noise)
        .unwrap();
    let d_fourier_bsk = cuda_engine
        .convert_lwe_bootstrap_key(&h_bootstrap_key)
        .unwrap();
    let d_fourier_ksk = cuda_engine
        .convert_lwe_keyswitch_key(&h_keyswitch_key)
        .unwrap();

    let input_wire_file: Option<String> =
        Some("./hdl-benchmarks/test-cases/32-bit-mult.inputs.csv".to_string());
    // Plaintext
    let input_wire_map = helm::get_input_wire_map(input_wire_file, vec![], "bool");

    let mut ptxt_wire_map = circuit.initialize_wire_map(&wire_set, &input_wire_map, datatype);

    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
    }
    ptxt_wire_map = circuit.evaluate(&ptxt_wire_map);

    let mut circuit = CircuitCuda::new(
        circuit,
        default_engine,
        cuda_engine,
        h_input_key,
        d_fourier_bsk,
        d_fourier_ksk,
        lwe_dim,
        noise,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);

    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let decrypted_outputs = EvalCircuit::decrypt_outputs(&mut circuit, &enc_wire_map, true);
    for key in decrypted_outputs.keys() {
        assert_eq!(ptxt_wire_map[key], decrypted_outputs[key]);
    }
    debug_println!("output wire map: {:?}", decrypted_outputs);
}

#[test]
fn encrypted_eight_bit_adder_lut() {
    let datatype = "bool";
    let (gates_set, wire_set, input_wires, _, _, _, _) = verilog_parser::read_verilog_file(
        "hdl-benchmarks/processed-netlists/8-bit-adder-lut-2-1.v",
        false,
    );
    let input_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/8-bit-adder.inputs.csv",
        datatype,
    );

    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);

    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();

    let mut ptxt_wire_map = circuit_ptxt.initialize_wire_map(&wire_set, &input_wire_map, datatype);

    // Encrypted single bit ctxt
    let (client_key, server_key) = tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_1_KS_PBS);

    // Plaintext
    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
    }
    ptxt_wire_map = circuit_ptxt.evaluate(&ptxt_wire_map);

    let mut circuit = LutCircuit::new(client_key.clone(), server_key, circuit_ptxt);
    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt(&enc_wire_map[wire_name]) == 1,
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], PtxtType::Bool(dec_wire_map[key]));
    }
    debug_println!("wire map: {:?}", dec_wire_map);
}

#[test]
fn encrypted_eight_bit_adder_high_precision_lut() {
    let datatype = "bool";
    let (gates_set, wire_set, input_wires, _, _, _, _) = verilog_parser::read_verilog_file(
        "hdl-benchmarks/processed-netlists/8-bit-adder-lut-high-precision.v",
        false,
    );
    let input_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/8-bit-adder.inputs.csv",
        datatype,
    );

    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();
    let mut ptxt_wire_map = circuit_ptxt.initialize_wire_map(&wire_set, &input_wire_map, datatype);

    // Encrypted
    let (client_key_shortint, server_key_shortint) =
        tfhe::shortint::gen_keys(PARAM_MESSAGE_1_CARRY_1); // single bit ctxt
    let client_key = ClientKeyInt::from(client_key_shortint.clone());
    let server_key = ServerKeyInt::from_shortint(&client_key, server_key_shortint.clone());

    let wopbs_key_shortint = WopbsKeyShortInt::new_wopbs_key(
        &client_key_shortint,
        &server_key_shortint,
        &WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    );
    let wopbs_key = WopbsKeyInt::from(wopbs_key_shortint.clone());

    // Plaintext
    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
    }
    ptxt_wire_map = circuit_ptxt.evaluate(&ptxt_wire_map);

    let mut circuit = HighPrecisionLutCircuit::new(
        wopbs_key_shortint,
        wopbs_key,
        client_key.clone(),
        server_key,
        circuit_ptxt,
    );
    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt_one_block(&enc_wire_map[wire_name]),
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], PtxtType::Bool(dec_wire_map[key] != 0));
    }
    debug_println!("wire map: {:?}", dec_wire_map);
}

#[test]
fn encrypted_chi_squared_arithmetic() {
    let datatype = "u16";
    let (gates_set, wire_set, input_wires, _, _, _, _) = verilog_parser::read_verilog_file(
        "hdl-benchmarks/processed-netlists/chi_squared_arith.v",
        true,
    );
    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();

    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            None,
        )
        .build();
    let (client_key, server_key) = generate_keys(config); // integer ctxt
    let mut circuit = ArithCircuit::new(client_key.clone(), server_key, circuit_ptxt);

    // Input set 1
    let input_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        datatype,
    );
    let output_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_1.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(value), PtxtType::U8(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U16(value), PtxtType::U16(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U32(value), PtxtType::U32(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U64(value), PtxtType::U64(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U128(value), PtxtType::U128(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }

    // Input set 2
    let input_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_2.inputs.csv",
        datatype,
    );
    let output_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_2.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 2, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(val), PtxtType::U8(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U16(val), PtxtType::U16(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U32(val), PtxtType::U32(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U64(val), PtxtType::U64(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U128(val), PtxtType::U128(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }

    // Input set 3
    let input_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_3.inputs.csv",
        datatype,
    );
    let output_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_3.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 3, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(val), PtxtType::U8(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U16(val), PtxtType::U16(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U32(val), PtxtType::U32(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U64(val), PtxtType::U64(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U128(val), PtxtType::U128(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }

    // Input set 4
    let input_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_4.inputs.csv",
        datatype,
    );
    let output_wire_map = verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_4.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 4, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(val), PtxtType::U8(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U16(val), PtxtType::U16(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U32(val), PtxtType::U32(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U64(val), PtxtType::U64(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U128(val), PtxtType::U128(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }
}
