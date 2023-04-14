use debug_print::debug_println;
use itertools::Itertools;
use std::collections::HashMap;

mod circuit;
mod verilog_parser;

fn main() {
    let (mut gates, mut output_map, inputs) = 
        verilog_parser::read_verilog_file("verilog-files/2bit_adder.v");
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
        output_map.insert(input.to_string(), true);
    }
    // circuit::_evaluate_circuit_sequentially(&mut gates, &mut output_map);
    circuit::evaluate_circuit_parallel(&mut level_map, &mut output_map);
    println!("Evaluated:");
    for wire_name in output_map.keys().sorted() {
        println!(" {}: {}", wire_name, output_map[wire_name]);
    }
}
