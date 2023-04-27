use clap::{Arg, Command};
use debug_print::debug_println;
use helm::{
    ascii,
    circuit,
    verilog_parser,
};
use itertools::Itertools;
use std::{
    collections::HashMap,
    time::Instant
};
use termion::color;
use tfhe::boolean::prelude::*;

fn main() {
    ascii::print_art();

    let matches = Command::new("HELM")
        .about("HELM: Homomorphic Evaluation with Lookup table Memoization")
        .arg(Arg::new("input")
            .long("input")
            .value_name("FILE")
            .help("Verilog input file to evaluate")
            .required(true))
        .arg(Arg::new("wires")
            .long("wires")
            .value_name("FILE")
            .help("Input wire values")
            .required(false))
        .arg(Arg::new("cycles")
            .long("cycles")
            .value_name("NUMBER")
            .help("Number of cycles for sequential circuits")
            .required(false)
            .default_value("1")
            .value_parser(clap::value_parser!(usize)))
        .get_matches();
    let file_name = matches.get_one::<String>("input").expect("Verilog input file is required");
    let num_cycles = *matches.get_one::<usize>("cycles").expect("required");
    
    let input_wire_map = {
        if matches.contains_id("wires") {
            let input_wires_file = matches.get_one::<String>("wires").unwrap();

            verilog_parser::read_input_wires(&input_wires_file)
        } else {
            println!("{}[!]{} No CSV file provided for the input wires, they will be initialized to false.", color::Fg(color::LightYellow), color::Fg(color::Reset));

            HashMap::new()
        }
    };

    let (mut gates, wire_map_im, inputs, dff_outputs, is_sequential) = 
        verilog_parser::read_verilog_file(file_name);
    
    if num_cycles > 1 && !is_sequential {
        panic!("Cannot run combinational circuit for more than one cycles.");
    }
    let mut level_map = circuit::compute_levels(&mut gates, &inputs);

    #[cfg(debug_assertions)]
    for level in level_map.keys().sorted() {
        println!("Level {}:", level);
        for gate in &level_map[level] {
            println!("  {:?}", gate);
        }
    }
    debug_println!();

    // Initialization of inputs to true
    let mut wire_map = wire_map_im.clone();
    for input_wire in &inputs {
        // if no inputs are provided, initialize it to false
        if input_wire_map.len() == 0 {
            wire_map.insert(input_wire.to_string(), false);
        } else if !input_wire_map.contains_key(input_wire) {
            panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
        } else {
            wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
        }
    }
    for wire in &dff_outputs {
        wire_map.insert(wire.to_string(), false);
    }
    debug_println!("before eval wire_map: {:?}", wire_map);

    for cycle in 0..num_cycles {
        // circuit::_evaluate_circuit_sequentially(&mut gates, &mut wire_map, cycle);
        wire_map = circuit::evaluate_circuit_parallel(&mut level_map, &wire_map, cycle);
        println!("Cycle {}) Evaluation:", cycle);
        for wire_name in wire_map.keys().sorted() {
            println!(" {}: {}", wire_name, wire_map[wire_name]);
        }
        println!();
    }

    // Encrypted evaluation
    let mut start = Instant::now();
    let (client_key, server_key) = gen_keys();
    println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

    // Client encrypts their inputs
    start = Instant::now();
    let mut enc_wire_map = HashMap::new();
    for (wire, value) in wire_map_im {
        enc_wire_map.insert(wire, client_key.encrypt(value));
    }
    for input_wire in &inputs {
        // if no inputs are provided, initialize it to false
        if input_wire_map.len() == 0 {
            enc_wire_map.insert(
                input_wire.to_string(),
                client_key.encrypt(false)
            );
        } else if !input_wire_map.contains_key(input_wire) {
            panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
        } else {
            enc_wire_map.insert(
                input_wire.to_string(), 
                client_key.encrypt(input_wire_map[input_wire])
            );
        }
    }
    for wire in &dff_outputs {
        enc_wire_map.insert(wire.to_string(), client_key.encrypt(false));
    }
    println!("Encryption done in {} seconds.", start.elapsed().as_secs_f64());

    for cycle in 0..num_cycles {
        start = Instant::now();
        enc_wire_map = circuit::evaluate_encrypted_circuit_parallel(&server_key, &mut level_map, &enc_wire_map, cycle);
        println!("Cycle {}) Evaluation done in {} seconds.\n", cycle, start.elapsed().as_secs_f64());
    }

    // Client decrypts the output of the circuit
    start = Instant::now();
    println!("Encrypted Evaluation:");
    for wire_name in enc_wire_map.keys().sorted() {
        println!(" {}: {}", wire_name, client_key.decrypt(&enc_wire_map[wire_name]));
    }
    println!("Decryption done in {} seconds.", start.elapsed().as_secs_f64());

    println!();
}
