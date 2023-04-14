use clap::{Arg, Command};
use debug_print::debug_println;
use itertools::Itertools;
use std::collections::HashMap;

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

    let (mut gates, mut wire_map, inputs) = 
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
    for input in &inputs {
        wire_map.insert(input.to_string(), true);
    }
    debug_println!("before eval wire_map: {:?}", wire_map);

    // circuit::_evaluate_circuit_sequentially(&mut gates, &mut wire_map);
    wire_map = circuit::evaluate_circuit_parallel(&mut level_map, &wire_map);
    println!("Evaluated:");
    for wire_name in wire_map.keys().sorted() {
        println!(" {}: {}", wire_name, wire_map[wire_name]);
    }
}
