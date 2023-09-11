use debug_print::debug_println;
use helm::{ascii, circuit, circuit::EvalCircuit, verilog_parser};
use std::time::Instant;
use termion::color;
use tfhe::{
    boolean::gen_keys, generate_keys, shortint::parameters::PARAM_MESSAGE_2_CARRY_1_KS_PBS, ConfigBuilder,
};

fn main() {
    ascii::print_art();
    let matches = helm::parse_args();
    let file_name = matches
        .get_one::<String>("verilog")
        .expect("Verilog input file is required");
    let num_cycles = *matches.get_one::<usize>("cycles").expect("required");
    let verbose = matches.get_flag("verbose");
    let inputs_filename = matches.get_one::<String>("input-wires-file").cloned();
    let outputs_filename = matches.get_one::<String>("output-wires-file").cloned();
    let arithmetic = matches.get_one::<String>("arithmetic");

    // TODO: Add support for this.
    // If it's arithmetic and the num_cycles variable has been set
    if arithmetic.is_some() && num_cycles > 1 {
        panic!("Arithmetic does not currently support sequential. Set num_cycles to 1.");
    }

    let wire_inputs = if let Some(occurrences) = matches.get_occurrences("input-wires") {
        occurrences
            .map(Iterator::collect)
            .collect::<Vec<Vec<&String>>>()
    } else {
        vec![]
    };

    let (gates_set, wire_set, input_wires, output_wires, dff_outputs, has_luts, _) =
        verilog_parser::read_verilog_file(file_name, arithmetic.is_some());

    let is_sequential = dff_outputs.len() > 1;
    if num_cycles > 1 && !is_sequential {
        panic!(
            "{}[!]{} Cannot run combinational circuit for more than one cycles.",
            color::Fg(color::LightRed),
            color::Fg(color::Reset)
        );
    }
    let mut circuit_ptxt =
        circuit::Circuit::new(gates_set, &input_wires, &output_wires, &dff_outputs);

    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();
    #[cfg(debug_assertions)]
    circuit_ptxt.print_level_map();
    debug_println!();

    if let Some(arithmetic_type) = arithmetic {
        println!(
            "{} -- Arithmetic mode with {} -- {}",
            color::Fg(color::LightYellow),
            arithmetic_type,
            color::Fg(color::Reset)
        );
        let arithmetic_type = arithmetic_type.as_str();
        match arithmetic_type {
            "u8" | "u16" | "u32" | "u64" | "u128" => {}
            _ => unreachable!(),
        }

        // Arithmetic mode
        let config = ConfigBuilder::all_disabled()
            .enable_custom_integers(
                tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
                None,
            )
            .build();
        let mut start = Instant::now();
        let (client_key, server_key) = generate_keys(config); // integer ctxt
        let mut circuit = circuit::ArithCircuit::new(client_key, server_key, circuit_ptxt);
        println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

        let input_wire_map =
            helm::get_input_wire_map(inputs_filename, wire_inputs, arithmetic_type);

        // Client encrypts their inputs
        start = Instant::now();
        let mut enc_wire_map =
            EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
        println!(
            "Encryption done in {} seconds.",
            start.elapsed().as_secs_f64()
        );

        // TODO: Add cycles here
        start = Instant::now();
        enc_wire_map =
            EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, arithmetic_type);
        println!(
            "Evaluation done in {} seconds.\n",
            start.elapsed().as_secs_f64()
        );

        // Client decrypts the output of the circuit
        start = Instant::now();
        println!("Encrypted Evaluation:");
        let decrypted_outputs = EvalCircuit::decrypt_outputs(&circuit, &enc_wire_map, verbose);
        verilog_parser::write_output_wires(outputs_filename, &decrypted_outputs);
        println!(
            "Decryption done in {} seconds.",
            start.elapsed().as_secs_f64()
        );
    } else {
        let arithmetic_type = "bool";
        // Initialization of inputs
        let input_wire_map =
            helm::get_input_wire_map(inputs_filename, wire_inputs, arithmetic_type);

        // Encrypted Evaluation
        if !has_luts {
            println!(
                "{} -- Gates mode -- {}",
                color::Fg(color::LightYellow),
                color::Fg(color::Reset)
            );

            // Gate mode
            let mut start = Instant::now();
            let (client_key, server_key) = gen_keys();
            println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());
            let mut circuit = circuit::GateCircuit::new(client_key, server_key, circuit_ptxt);

            // Client encrypts their inputs
            start = Instant::now();
            let mut enc_wire_map =
                EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
            println!(
                "Encryption done in {} seconds.",
                start.elapsed().as_secs_f64()
            );

            for cycle in 0..num_cycles {
                start = Instant::now();
                enc_wire_map = EvalCircuit::evaluate_encrypted(
                    &mut circuit,
                    &enc_wire_map,
                    1,
                    arithmetic_type,
                );
                println!(
                    "Cycle {}) Evaluation done in {} seconds.\n",
                    cycle,
                    start.elapsed().as_secs_f64()
                );
            }

            // Client decrypts the output of the circuit
            start = Instant::now();
            println!("Encrypted Evaluation:");
            let decrypted_outputs = EvalCircuit::decrypt_outputs(&circuit, &enc_wire_map, verbose);
            verilog_parser::write_output_wires(outputs_filename, &decrypted_outputs);
            println!(
                "Decryption done in {} seconds.",
                start.elapsed().as_secs_f64()
            );
        } else {
            println!(
                "{} -- LUTs mode -- {}",
                color::Fg(color::LightYellow),
                color::Fg(color::Reset)
            );

            // LUT mode
            let mut start = Instant::now();
            let (client_key, server_key) = tfhe::shortint::gen_keys(PARAM_MESSAGE_2_CARRY_1_KS_PBS); // single bit ctxt
            let mut circuit = circuit::LutCircuit::new(client_key, server_key, circuit_ptxt);
            println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

            // Client encrypts their inputs
            start = Instant::now();
            let mut enc_wire_map =
                EvalCircuit::encrypt_inputs(&mut circuit, &wire_set, &input_wire_map);
            println!(
                "Encryption done in {} seconds.",
                start.elapsed().as_secs_f64()
            );

            for cycle in 0..num_cycles {
                start = Instant::now();
                enc_wire_map = EvalCircuit::evaluate_encrypted(
                    &mut circuit,
                    &enc_wire_map,
                    1,
                    arithmetic_type,
                );
                println!(
                    "Cycle {}) Evaluation done in {} seconds.\n",
                    cycle,
                    start.elapsed().as_secs_f64()
                );
            }

            // Client decrypts the output of the circuit
            start = Instant::now();
            println!("Encrypted Evaluation:");
            let decrypted_outputs = EvalCircuit::decrypt_outputs(&circuit, &enc_wire_map, verbose);
            verilog_parser::write_output_wires(outputs_filename, &decrypted_outputs);
            println!(
                "Decryption done in {} seconds.",
                start.elapsed().as_secs_f64()
            );
        }
    }
    println!();
}
