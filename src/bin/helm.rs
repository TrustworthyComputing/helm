use clap::{Arg, ArgAction, Command};
use debug_print::debug_println;
use helm::{ascii, circuit, circuit::EvalCircuit, verilog_parser};
use std::{collections::HashMap, time::Instant};
use termion::color;
use tfhe::{boolean::prelude::*, shortint::parameters::PARAM_MESSAGE_4_CARRY_0};
use tfhe::{generate_keys, set_server_key, ConfigBuilder};

fn parse_args() -> (String, usize, bool, HashMap<String, bool>) {
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
        .get_matches();
    let file_name = matches
        .get_one::<String>("input")
        .expect("Verilog input file is required");
    let num_cycles = *matches.get_one::<usize>("cycles").expect("required");
    let verbose = matches.get_flag("verbose");

    let input_wire_map = {
        if matches.contains_id("wires") {
            let input_wires_file = matches.get_one::<String>("wires").unwrap();

            verilog_parser::read_input_wires(input_wires_file)
        } else {
            println!(
                "{}[!]{} No CSV file provided for the input wires,
                they will be initialized to false.",
                color::Fg(color::LightYellow),
                color::Fg(color::Reset)
            );

            HashMap::new()
        }
    };

    (file_name.to_string(), num_cycles, verbose, input_wire_map)
}

fn main() {
    ascii::print_art();
    let (file_name, num_cycles, verbose, input_wire_map) = parse_args();
    let (gates_set, wire_map_im, input_wires, output_wires, dff_outputs, is_sequential, has_luts, has_arith) =
        verilog_parser::read_verilog_file(&file_name);

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

    let mut circuit_ptxt =
        circuit::Circuit::new(gates_set, &input_wires, &output_wires, &dff_outputs);

    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();
    #[cfg(debug_assertions)]
    circuit_ptxt.print_level_map();
    debug_println!();

    // Initialization of inputs
    let mut wire_map = circuit_ptxt.initialize_wire_map(&wire_map_im, &input_wire_map);
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
    if !has_luts && !has_arith {
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
            EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
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
    } else if has_arith {
        println!(
            "{} -- Arithmetic mode -- {}",
            color::Fg(color::LightYellow),
            color::Fg(color::Reset)
        );

        // Arithmetic mode
        // let config = ConfigBuilder::all_disabled()
        // .enable_custom_integers(
        //    tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
        //    None,
        // )
        // .build();
        // let mut start = Instant::now();
        // let (client_key, server_key) = generate_keys(config); // integer ctxt
        // set_server_key(server_key);
        // let mut circuit = circuit::ArithCircuit::new(client_key, server_key, circuit_ptxt);
        // println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

        // Client encrypts their inputs
        // start = Instant::now();
        // let mut enc_wire_map =
        //     EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
        // println!(
        //     "Encryption done in {} seconds.",
        //     start.elapsed().as_secs_f64()
        // );

        // for cycle in 0..num_cycles {
        //     start = Instant::now();
        //     enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
        //     println!(
        //         "Cycle {}) Evaluation done in {} seconds.\n",
        //         cycle,
        //         start.elapsed().as_secs_f64()
        //     );
        // }

        // // Client decrypts the output of the circuit
        // start = Instant::now();
        // println!("Encrypted Evaluation:");
        // EvalCircuit::decrypt_outputs(&circuit, &enc_wire_map, verbose);
        // println!(
        //     "Decryption done in {} seconds.",
        //     start.elapsed().as_secs_f64()
        // );
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
            EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
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
    println!();
}
