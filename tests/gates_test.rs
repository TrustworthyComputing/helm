use helm::{
    gates::{Gate, GateType},
    FheType, PtxtType,
};
use rand::Rng;
use tfhe::boolean::gen_keys;

#[test]
fn encrypted_vs_plaintext_gates() {
    let (client_key, server_key) = gen_keys();

    let ptxts = vec![PtxtType::Bool(true), PtxtType::Bool(false)];
    let ctxts = vec![client_key.encrypt(true), client_key.encrypt(false)];
    let gates = vec![
        Gate::new(
            String::from(""),
            GateType::And,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Or,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Nor,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Xor,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Nand,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Not,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Xnor,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Mux,
            vec![],
            None,
            "".to_string(),
            0,
        ),
    ];
    let mut rng = rand::thread_rng();
    let mut cycle = 1;
    for mut gate in gates {
        for i in 0..2 {
            for j in 0..2 {
                let mut inputs_ptxt = vec![ptxts[i], ptxts[j]];
                let mut inputs_ctxt = vec![ctxts[i].clone(), ctxts[j].clone()];
                if gate.get_gate_type() == GateType::Mux {
                    let select: bool = rng.gen();
                    inputs_ptxt.push(PtxtType::Bool(select));
                    inputs_ctxt.push(client_key.encrypt(select));
                }
                let output_value_ptxt = gate.evaluate(&inputs_ptxt);

                let output_value_ctxt = gate.evaluate_encrypted(&server_key, &inputs_ctxt, cycle);
                if gate.get_gate_type() == GateType::Lut {
                    continue;
                }

                assert_eq!(
                    output_value_ptxt,
                    PtxtType::Bool(client_key.decrypt(&output_value_ctxt))
                );

                cycle += 1;
            }
        }
    }
}

#[test]
fn caching_of_gate_evaluation() {
    use std::time::Instant;
    use tfhe::prelude::*;
    use tfhe::set_server_key;
    use tfhe::FheUint16;
    use tfhe::{generate_keys, ConfigBuilder};

    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            None,
        )
        .build();
    let (client_key, server_key) = generate_keys(config); // integer ctxt
    set_server_key(server_key);

    let ptxt = vec![10, 20, 30, 40];
    let inputs_ctxt = vec![
        FheType::U16(FheUint16::try_encrypt(ptxt[0], &client_key).unwrap()),
        FheType::U16(FheUint16::try_encrypt(ptxt[1], &client_key).unwrap()),
        FheType::U16(FheUint16::try_encrypt(ptxt[2], &client_key).unwrap()),
        FheType::U16(FheUint16::try_encrypt(ptxt[3], &client_key).unwrap()),
    ];

    let mut gates = vec![
        Gate::new(
            String::from(""),
            GateType::Add,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Sub,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Mult,
            vec![],
            None,
            "".to_string(),
            0,
        ),
    ];

    for gate in gates.iter_mut() {
        let mut cycle = 1;

        let mut start = Instant::now();
        let (result, ptxt_result) = match gate.get_gate_type() {
            GateType::Add => (
                gate.evaluate_encrypted_add_block(&inputs_ctxt[0], &inputs_ctxt[1], cycle),
                PtxtType::U16(ptxt[0] + ptxt[1]),
            ),
            GateType::Sub => (
                gate.evaluate_encrypted_sub_block(&inputs_ctxt[1], &inputs_ctxt[0], cycle),
                PtxtType::U16(ptxt[1] - ptxt[0]),
            ),
            GateType::Mult => (
                gate.evaluate_encrypted_mul_block(&inputs_ctxt[0], &inputs_ctxt[1], cycle),
                PtxtType::U16(ptxt[0] * ptxt[1]),
            ),
            _ => unreachable!(),
        };
        let mut elapsed = start.elapsed().as_secs_f64();
        let mut decrypted = result.decrypt(&client_key);
        match gate.get_gate_type() {
            GateType::Add => {
                println!(
                    "Cycle {}) {}+{}={} in {} seconds",
                    cycle, ptxt[0], ptxt[1], decrypted, elapsed
                );
            }
            GateType::Sub => {
                println!(
                    "Cycle {}) {}-{}={} in {} seconds",
                    cycle, ptxt[1], ptxt[0], decrypted, elapsed
                );
            }
            GateType::Mult => {
                println!(
                    "Cycle {}) {}*{}={} in {} seconds",
                    cycle, ptxt[0], ptxt[1], decrypted, elapsed
                );
            }
            _ => unreachable!(),
        };
        assert_eq!(decrypted, ptxt_result);

        // These should have been cached since the cycle is the same.
        start = Instant::now();
        let result = match gate.get_gate_type() {
            GateType::Add => {
                gate.evaluate_encrypted_add_block(&inputs_ctxt[2], &inputs_ctxt[3], cycle)
            }
            GateType::Sub => {
                gate.evaluate_encrypted_sub_block(&inputs_ctxt[3], &inputs_ctxt[2], cycle)
            }
            GateType::Mult => {
                gate.evaluate_encrypted_mul_block(&inputs_ctxt[2], &inputs_ctxt[3], cycle)
            }
            _ => unreachable!(),
        };
        let elapsed_cached = start.elapsed().as_secs_f64();
        decrypted = result.decrypt(&client_key);
        assert_eq!(decrypted, ptxt_result);
        assert!(elapsed_cached < elapsed);

        cycle += 1;

        start = Instant::now();
        let (result, ptxt_result) = match gate.get_gate_type() {
            GateType::Add => (
                gate.evaluate_encrypted_add_block(&inputs_ctxt[1], &inputs_ctxt[2], cycle),
                PtxtType::U16(ptxt[1] + ptxt[2]),
            ),
            GateType::Sub => (
                gate.evaluate_encrypted_sub_block(&inputs_ctxt[2], &inputs_ctxt[1], cycle),
                PtxtType::U16(ptxt[2] - ptxt[1]),
            ),
            GateType::Mult => (
                gate.evaluate_encrypted_mul_block(&inputs_ctxt[1], &inputs_ctxt[2], cycle),
                PtxtType::U16(ptxt[1] * ptxt[2]),
            ),
            _ => unreachable!(),
        };
        elapsed = start.elapsed().as_secs_f64();
        decrypted = result.decrypt(&client_key);
        match gate.get_gate_type() {
            GateType::Add => {
                println!(
                    "Cycle {}) {}+{}={} in {} seconds",
                    cycle, ptxt[1], ptxt[2], decrypted, elapsed
                );
            }
            GateType::Sub => {
                println!(
                    "Cycle {}) {}-{}={} in {} seconds",
                    cycle, ptxt[2], ptxt[1], decrypted, elapsed
                );
            }
            GateType::Mult => {
                println!(
                    "Cycle {}) {}*{}={} in {} seconds",
                    cycle, ptxt[1], ptxt[2], decrypted, elapsed
                );
            }
            _ => unreachable!(),
        };
        assert_eq!(decrypted, ptxt_result);

        cycle += 1;

        start = Instant::now();
        let (result, ptxt_result) = match gate.get_gate_type() {
            GateType::Add => (
                gate.evaluate_encrypted_add_block(&inputs_ctxt[2], &inputs_ctxt[3], cycle),
                PtxtType::U16(ptxt[2] + ptxt[3]),
            ),
            GateType::Sub => (
                gate.evaluate_encrypted_sub_block(&inputs_ctxt[3], &inputs_ctxt[2], cycle),
                PtxtType::U16(ptxt[3] - ptxt[2]),
            ),
            GateType::Mult => (
                gate.evaluate_encrypted_mul_block(&inputs_ctxt[2], &inputs_ctxt[3], cycle),
                PtxtType::U16(ptxt[2] * ptxt[3]),
            ),
            _ => unreachable!(),
        };
        elapsed = start.elapsed().as_secs_f64();
        decrypted = result.decrypt(&client_key);
        match gate.get_gate_type() {
            GateType::Add => {
                println!(
                    "Cycle {}) {}+{}={} in {} seconds",
                    cycle, ptxt[2], ptxt[3], decrypted, elapsed
                );
            }
            GateType::Sub => {
                println!(
                    "Cycle {}) {}-{}={} in {} seconds",
                    cycle, ptxt[3], ptxt[2], decrypted, elapsed
                );
            }
            GateType::Mult => {
                println!(
                    "Cycle {}) {}*{}={} in {} seconds",
                    cycle, ptxt[2], ptxt[3], decrypted, elapsed
                );
            }
            _ => unreachable!(),
        };
        assert_eq!(decrypted, ptxt_result);
    }
}
