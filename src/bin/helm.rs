use clap::{arg, Arg, Command, ArgAction};
use debug_print::debug_println;
use helm::{
    ascii,
    circuit,
    circuit::EvalCircuit,
    verilog_parser,
};
use std::{
    collections::{HashMap},
    time::Instant
};
use termion::color;
use tfhe::{
    boolean::prelude::*,
    integer::{
        ServerKey as ServerKeyInt,
        ClientKey as ClientKeyInt,
        wopbs::WopbsKey as WopbsKeyInt,
    },
    shortint::{
        wopbs::WopbsKey as WopbsKeyShortInt,  
        parameters::{
            parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_1_CARRY_0,
            PARAM_MESSAGE_1_CARRY_0,
        },      
    },
};

#[cfg(debug_assertions)]
use itertools::Itertools;

fn eval_lut_circuit(
    level_map: HashMap<usize, Vec<helm::circuit::Gate>>, 
    mut wire_map: HashMap<String, bool>,
    num_cycles: usize,
    wire_map_im: HashMap<String, bool, std::collections::hash_map::RandomState>,
    input_wire_map: HashMap<String, bool, std::collections::hash_map::RandomState>,
    inputs: Vec<String>,
    dff_outputs: Vec<String>,
) {
    let mut start = Instant::now();
    // Generate the client key and the server key:
    let (cks_shortint, sks_shortint) = tfhe::shortint::gen_keys(PARAM_MESSAGE_1_CARRY_0); // single bit ctxt
    let cks = ClientKeyInt::from(cks_shortint.clone());
    let sks = ServerKeyInt::from_shortint(&cks, sks_shortint.clone());
    let wopbs_key_shortint = WopbsKeyShortInt::new_wopbs_key(&cks_shortint, &sks_shortint, &&WOPBS_PARAM_MESSAGE_1_CARRY_0);
    let wopbs_key = WopbsKeyInt::from(wopbs_key_shortint.clone());
    println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

    let mut circuit = circuit::LutCircuit::new(wopbs_key_shortint, wopbs_key, sks, level_map);

    for cycle in 0..num_cycles {
        wire_map = EvalCircuit::evaluate(&mut circuit, &wire_map, 1);
        println!("Cycle {}) Evaluation:", cycle);
        // for wire_name in wire_map.keys().sorted() {
        //     println!(" {}: {}", wire_name, wire_map[wire_name]);
        // }
        // println!();
    }

    // Client encrypts their inputs
    start = Instant::now();
    let mut enc_wire_map = HashMap::new();
    for (wire, value) in wire_map_im {
        enc_wire_map.insert(wire, cks.encrypt_one_block(value as u64));
    }
    for input_wire in &inputs {
        // if no inputs are provided, initialize it to false
        if input_wire_map.len() == 0 {
            enc_wire_map.insert(
                input_wire.to_string(),
                cks.encrypt_one_block(0)
            );
        } else if !input_wire_map.contains_key(input_wire) {
            panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
        } else {
            enc_wire_map.insert(
                input_wire.to_string(), 
                cks.encrypt_one_block(input_wire_map[input_wire] as u64)
            );
        }
    }
    for wire in &dff_outputs {
        enc_wire_map.insert(wire.to_string(), cks.encrypt_one_block(0));
    }
    println!("Encryption done in {} seconds.", start.elapsed().as_secs_f64());

    for cycle in 0..num_cycles {
        start = Instant::now();
        enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
        println!("Cycle {}) Evaluation done in {} seconds.\n", cycle, start.elapsed().as_secs_f64());
    }

    // Client decrypts the output of the circuit
    start = Instant::now();
    println!("Encrypted Evaluation:");
    // for wire_name in enc_wire_map.keys().sorted() {
    //     println!(" {}: {}", wire_name, cks.decrypt_one_block(&enc_wire_map[wire_name]));
    // }
    println!("Decryption done in {} seconds.", start.elapsed().as_secs_f64());

    println!();
}

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
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Turn verbose printing on")
            .action(ArgAction::SetTrue))
        .arg(arg!(
            -v --verbose ... "Turn verbose printing on"
        ))
        .get_matches();
    let file_name = matches.get_one::<String>("input").expect("Verilog input file is required");
    let num_cycles = *matches.get_one::<usize>("cycles").expect("required");
    let verbose = matches.get_flag("verbose");

    let input_wire_map = {
        if matches.contains_id("wires") {
            let input_wires_file = matches.get_one::<String>("wires").unwrap();

            verilog_parser::read_input_wires(&input_wires_file)
        } else {
            println!("{}[!]{} No CSV file provided for the input wires, they will be initialized to false.", color::Fg(color::LightYellow), color::Fg(color::Reset));

            HashMap::new()
        }
    };

    let (mut gates_set, wire_map_im, inputs, outputs, dff_outputs, is_sequential, has_luts) = 
        verilog_parser::read_verilog_file(file_name);
    
    if num_cycles > 1 && !is_sequential {
        panic!("Cannot run combinational circuit for more than one cycles.");
    }
    let mut ordered_gates = circuit::sort_circuit(&mut gates_set, &inputs);
    let level_map = circuit::compute_levels(&mut ordered_gates, &inputs);

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

    // Encrypted evaluation
    if has_luts {
        eval_lut_circuit(level_map, wire_map, num_cycles, wire_map_im, input_wire_map, inputs, dff_outputs);
        return;
    }
    let mut start = Instant::now();
    let (client_key, server_key) = gen_keys();
    println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

    let mut circuit = circuit::GateCircuit::new(Some(server_key), level_map);

    for cycle in 0..num_cycles {
        wire_map = EvalCircuit::evaluate(&mut circuit, &wire_map, 1);
        println!("Cycle {}) Evaluation:", cycle);
        
        #[cfg(debug_assertions)]
        for wire_name in wire_map.keys().sorted() {
            println!(" {}: {}", wire_name, wire_map[wire_name]);
        }
        #[cfg(debug_assertions)]
        println!();
    }

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
        enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
        println!("Cycle {}) Evaluation done in {} seconds.\n", cycle, start.elapsed().as_secs_f64());
    }

    // Client decrypts the output of the circuit
    start = Instant::now();
    println!("Encrypted Evaluation:");
    // for (i, wire_name) in enc_wire_map.keys().sorted().enumerate() {
    for (i, output_wire) in outputs.iter().enumerate() {
        if i > 10 && !verbose {
            println!("{}[!]{} More than ten outputs, pass `--verbose` to see output.", color::Fg(color::LightYellow), color::Fg(color::Reset));
            break;
        } else {
            println!(" {}: {}", output_wire, client_key.decrypt(&enc_wire_map[output_wire]));
        }
    }
    println!("Decryption done in {} seconds.", start.elapsed().as_secs_f64());

    println!();
}
