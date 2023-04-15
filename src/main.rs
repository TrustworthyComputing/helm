use clap::{Arg, Command};
use debug_print::debug_println;
use itertools::Itertools;
use std::{
    collections::HashMap,
    time::Instant,
};
use tfhe::boolean::prelude::*;

mod circuit;
mod verilog_parser;

fn main() {
    let matches = Command::new("HELM")
        .about("HELM: Homomorphic Evaluation with Lookup table Memoization")
        .arg(Arg::new("input")
            .long("input")
            .value_name("FILE")
            .help("Sets the input file to use")
            .required(true))
        .get_matches();
    let file_name = matches.get_one::<String>("input").expect("required");

    let (mut gates, wire_map_im, inputs) = 
        verilog_parser::read_verilog_file(file_name);
    debug_println!("inputs: {:?}", inputs);

    // Initialization of inputs to true
    let mut wire_levels = HashMap::new();
    for input in &inputs {
        wire_levels.insert(input.to_string(), 0);
    }

    let mut level_map = circuit::compute_levels(&mut gates, &mut wire_levels);
    
    for level in level_map.keys().sorted() {
        println!("Level {}:", level);
        for gate in &level_map[level] {
            println!("  {:?}", gate);
        }
    }
    println!();

    // Initialization of inputs to true
    let mut wire_map = wire_map_im.clone();
    for input_wire in &inputs {
        wire_map.insert(input_wire.to_string(), true);
    }
    debug_println!("before eval wire_map: {:?}", wire_map);

    // circuit::_evaluate_circuit_sequentially(&mut gates, &mut wire_map);
    wire_map = circuit::evaluate_circuit_parallel(&mut level_map, &wire_map);
    println!("Evaluation:");
    for wire_name in wire_map.keys().sorted() {
        println!(" {}: {}", wire_name, wire_map[wire_name]);
    }
    println!();

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
        enc_wire_map.insert(input_wire.to_string(), client_key.encrypt(true));
    }
    println!("Encryption done in {} seconds.", start.elapsed().as_secs_f64());

    start = Instant::now();
    enc_wire_map = circuit::evaluate_encrypted_circuit_parallel(&server_key, &mut level_map, &enc_wire_map);
    println!("Evaluation done in {} seconds.", start.elapsed().as_secs_f64());

    // Client decrypts the output of the circuit
    start = Instant::now();
    println!("Encrypted Evaluation:");
    for wire_name in enc_wire_map.keys().sorted() {
        println!(" {}: {}", wire_name, client_key.decrypt(&enc_wire_map[wire_name]));
    }
    println!("Decryption done in {} seconds.", start.elapsed().as_secs_f64());

    println!();
}
