use clap::{{Arg, ArgAction, Command}, builder::PossibleValue};
use debug_print::debug_println;
use helm::{ascii, circuit, circuit::EvalCircuit, get_input_wire_map, verilog_parser, PtxtType};
use std::time::Instant;
use termion::color;
use tfhe::{boolean::prelude::*, shortint::parameters::PARAM_MESSAGE_4_CARRY_0};
use tfhe::{generate_keys, ConfigBuilder};

fn parse_args() -> (String, usize, bool, Option<String>, Option<String>) {
    let matches = Command::new("HELM")
        .about("HELM: Homomorphic Evaluation with EDA-driven Logic Minimization")
        .arg(
            Arg::new("input")
                .long("input")
                .value_name("FILE")
                .help("Verilog input file to evaluate")
                .required(true),
        )
        .arg(
            Arg::new("wires")
                .long("wires")
                .value_name("FILE")
                .help("Input wire values")
                .required(false),
        )
        .arg(
            Arg::new("cycles")
                .long("cycles")
                .value_name("NUMBER")
                .help("Number of cycles for sequential circuits")
                .required(false)
                .default_value("1")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Turn verbose printing on")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("arithmetic")
                .long("arithmetic")
                .value_name("TYPE")
                .help("Datatype for arithmetic evaluation")
                .value_parser([
                    // PossibleValue::new("u8"),
                    // PossibleValue::new("u16"),
                    PossibleValue::new("u32"),
                    // PossibleValue::new("u64"),
                    // PossibleValue::new("u128"),
                ])
                .required(false)
        )
        .get_matches();
    let file_name = matches
        .get_one::<String>("input")
        .expect("Verilog input file is required");
    let num_cycles = *matches.get_one::<usize>("cycles").expect("required");
    let verbose = matches.get_flag("verbose");
    let wires_file = matches.get_one::<String>("wires").cloned();
    let arithmetic = matches.get_one::<String>("arithmetic").cloned();

    // TODO: Add support for this.
    // If it's arithmetic and the num_cycles variable has been set
    if let Some(_) = arithmetic {
        if num_cycles > 1 {
            panic!("Arithmetic does not currently support sequential. Set num_cycles to 1.");
        }
    }

    (
        file_name.to_string(),
        num_cycles,
        verbose,
        arithmetic,
        wires_file,
    )
}

fn main() {
    ascii::print_art();
    let (file_name, num_cycles, verbose, arithmetic, wire_file) = parse_args();
    // TODO: combine these
    let input_wire_map_bool;
    let input_wire_map_int;
    if let Some(arithmetic_type) = arithmetic {
        println!(
            "{} -- Arithmetic mode with {} -- {}",
            color::Fg(color::LightYellow),
            arithmetic_type,
            color::Fg(color::Reset)
        );

        input_wire_map_int = get_input_wire_map::<u32>(wire_file);
        let (gates_set, wire_map_im, input_wires, output_wires, dff_outputs, _, _) =
            verilog_parser::read_verilog_file::<u32>(&file_name, true);
        let mut circuit_ptxt =
            circuit::Circuit::new(gates_set.clone(), &input_wires, &output_wires, &dff_outputs);

        // TODO: move this check in the parser
        if gates_set.is_empty() {
            panic!(
                "{}[!]{} Parser error, no arithmetic gates detected.",
                color::Fg(color::LightRed),
                color::Fg(color::Reset)
            );
        }
        circuit_ptxt.sort_circuit();
        circuit_ptxt.compute_levels();
        #[cfg(debug_assertions)]
        circuit_ptxt.print_level_map();
        debug_println!();

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

        // Client encrypts their inputs
        start = Instant::now();
        let mut enc_wire_map =
            EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map_int);
        println!(
            "Encryption done in {} seconds.",
            start.elapsed().as_secs_f64()
        );

        // TODO: Add cycles here
        start = Instant::now();
        enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
        println!(
            "Evaluation done in {} seconds.\n",
            start.elapsed().as_secs_f64()
        );

        // Client decrypts the output of the circuit
        start = Instant::now();
        println!("Encrypted Evaluation:");
        EvalCircuit::decrypt_outputs(&circuit, &enc_wire_map, verbose);
        println!(
            "Decryption done in {} seconds.",
            start.elapsed().as_secs_f64()
        );
    } else {
        input_wire_map_bool = get_input_wire_map::<bool>(wire_file);
        let (gates_set, wire_map_im, input_wires, output_wires, dff_outputs, has_luts, _) =
            verilog_parser::read_verilog_file::<bool>(&file_name, false);
        let is_sequential = dff_outputs.len() > 1;
        let mut circuit_ptxt =
            circuit::Circuit::new(gates_set.clone(), &input_wires, &output_wires, &dff_outputs);
        if num_cycles > 1 && !is_sequential {
            panic!(
                "{}[!]{} Cannot run combinational circuit for more than one cycles.",
                color::Fg(color::LightRed),
                color::Fg(color::Reset)
            );
        }
        if gates_set.is_empty() {
            panic!(
                "{}[!]{} Parser error, no gates detected. Make sure to use the \
                'no-expr' flag in Yosys.",
                color::Fg(color::LightRed),
                color::Fg(color::Reset)
            );
        }
        circuit_ptxt.sort_circuit();
        circuit_ptxt.compute_levels();
        #[cfg(debug_assertions)]
        circuit_ptxt.print_level_map();
        debug_println!();

        // Initialization of inputs
        let mut wire_map =
            circuit_ptxt.initialize_wire_map::<bool>(&wire_map_im, &input_wire_map_bool);
        debug_println!("before eval wire_map: {:?}", wire_map);

        // Plaintext evaluation
        for cycle in 0..num_cycles {
            wire_map = circuit_ptxt.evaluate(&wire_map, 1);
            println!("Cycle {}) Evaluation:", cycle);

            #[cfg(debug_assertions)]
            for wire_name in &output_wires {
                println!(" {}: {}", wire_name, wire_map[wire_name]);
            }
            #[cfg(debug_assertions)]
            println!();
        }

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
                EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map_bool);
            println!(
                "Encryption done in {} seconds.",
                start.elapsed().as_secs_f64()
            );

            for cycle in 0..num_cycles {
                start = Instant::now();
                enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
                println!(
                    "Cycle {}) Evaluation done in {} seconds.\n",
                    cycle,
                    start.elapsed().as_secs_f64()
                );
            }

            // Client decrypts the output of the circuit
            start = Instant::now();
            println!("Encrypted Evaluation:");
            EvalCircuit::decrypt_outputs(&circuit, &enc_wire_map, verbose);
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
            let (client_key, server_key) = tfhe::shortint::gen_keys(PARAM_MESSAGE_4_CARRY_0); // single bit ctxt
            let mut circuit = circuit::LutCircuit::new(client_key, server_key, circuit_ptxt);
            println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

            // Client encrypts their inputs
            start = Instant::now();
            let mut enc_wire_map =
                EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map_bool);
            println!(
                "Encryption done in {} seconds.",
                start.elapsed().as_secs_f64()
            );

            for cycle in 0..num_cycles {
                start = Instant::now();
                enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
                println!(
                    "Cycle {}) Evaluation done in {} seconds.\n",
                    cycle,
                    start.elapsed().as_secs_f64()
                );
            }

            // Client decrypts the output of the circuit
            start = Instant::now();
            println!("Encrypted Evaluation:");
            EvalCircuit::decrypt_outputs(&circuit, &enc_wire_map, verbose);
            println!(
                "Decryption done in {} seconds.",
                start.elapsed().as_secs_f64()
            );
        }
    }
    println!();
}
