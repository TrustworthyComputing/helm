use debug_print::debug_println;
use itertools::Itertools;
use rayon::prelude::*;
use std::{
    collections::{HashMap, hash_map::Entry},
    // thread,
    sync::{RwLock, Arc},
    vec,
};
use tfhe::boolean::prelude::*;

#[cfg(test)]
use rand::Rng;

#[derive(Clone, Debug, PartialEq)]
pub enum GateType {
    And,
    Dff,
    Mux,
    Nand,
    Nor,
    Not,
    Or,
    Xnor,
    Xor,
}

#[derive(Clone, Debug)]
pub struct Gate {
    _gate_name: String,
    gate_type: GateType,
    input_wires: Vec<String>,
    output_wire: String,
    level: usize,
    cycle: usize,
    output: Option<bool>,
    encrypted_output: Option<Ciphertext>,
}

impl Gate {
    pub fn new(
        _gate_name: String, 
        gate_type: GateType,
        input_wires: Vec<String>,
        output_wire: String,
        level: usize
    ) -> Self {
        Gate {
            _gate_name,
            gate_type,
            input_wires,
            output_wire,
            level,
            cycle: 0,
            output: None,
            encrypted_output: None,
        }
    }
    
    pub fn get_output_wire(&self) -> String {
        self.output_wire.clone()
    }

    pub fn get_gate_type(&self) -> GateType {
        self.gate_type.clone()
    }

    fn evaluate(&mut self, input_values: &Vec<bool>, cycle: usize) -> bool {
        if let Some(output) = self.output.clone() {
            if self.cycle == cycle {
                return output;
            }
        }
        let output = match self.gate_type {
            GateType::And => input_values.iter().all(|&v| v),
            GateType::Dff => input_values[0],
            GateType::Mux => {
                let select_bit = input_values[2];
                (select_bit && input_values[0]) || (!select_bit && input_values[1])
            },
            GateType::Nand => !input_values.iter().all(|&v| v),
            GateType::Nor => !input_values.iter().any(|&v| v),
            GateType::Not => !input_values[0],
            GateType::Or => input_values.iter().any(|&v| v),
            GateType::Xnor => input_values.iter().filter(|&&v| v).count() % 2 != 1,
            GateType::Xor => input_values.iter().filter(|&&v| v).count() % 2 == 1,
        };

        self.output = Some(output);
        self.cycle = cycle;
        output
    }

    fn evaluate_encrypted(
        &mut self,
        server_key: &ServerKey,
        input_values: &Vec<Ciphertext>,
        cycle: usize,
    ) -> Ciphertext {
        if let Some(encrypted_output) = self.encrypted_output.clone() {
            if self.cycle == cycle {
                return encrypted_output;
            }
        }
        let encrypted_output = match self.gate_type {
            GateType::And => server_key.
                and(&input_values[0], &input_values[1]),
            GateType::Dff => input_values[0].clone(),
            GateType::Mux => server_key.mux(&input_values[2],
                &input_values[0], &input_values[1]),
            GateType::Nand => server_key.
                nand(&input_values[0], &input_values[1]),
            GateType::Nor => server_key.
                nor(&input_values[0], &input_values[1]),
            GateType::Not => server_key.not(&input_values[0]),
            GateType::Or => server_key.
                or(&input_values[0], &input_values[1]),
            GateType::Xnor => server_key.
                xnor(&input_values[0], &input_values[1]),
            GateType::Xor => server_key.
                xor(&input_values[0], &input_values[1]),
        };

        self.encrypted_output = Some(encrypted_output.clone());
        encrypted_output
    }
}

// Sort the gates by level so they can be evaluated later in parallel.
pub fn compute_levels(
    gates: &mut Vec<Gate>, inputs: &Vec<String>
) -> HashMap::<usize, Vec<Gate>> {
    // Initialization of inputs to true
    let mut wire_levels = HashMap::new();
    for input in inputs {
        wire_levels.insert(input.to_string(), 0);
    }
    
    let mut level_map = HashMap::new();
    for mut gate in gates {
        if gate.gate_type == GateType::Dff {
            match level_map.entry(std::usize::MAX) {
                Entry::Vacant(e) => { e.insert(vec![(*gate).clone()]); },
                Entry::Occupied(mut e) => { e.get_mut().push((*gate).clone()); }
            }
            gate.level = std::usize::MAX;
            continue;
        }
        // Find the max depth of the input wires
        let mut depth = 0;
        gate.input_wires.iter().for_each(|input| {
            let input_depth = match wire_levels.get(input) {
                Some(value) => *value,
                None => panic!("Input {} not found in wire_map", input),
            };
            depth = std::cmp::max(depth, input_depth + 1);
        });

        match level_map.entry(depth) {
            Entry::Vacant(e) => { e.insert(vec![(*gate).clone()]); },
            Entry::Occupied(mut e) => { e.get_mut().push((*gate).clone()); }
        }
        gate.level = depth;
        wire_levels.insert(gate.get_output_wire(), depth);
    }

    level_map
}

// Evaluate each gate in topological order
pub fn _evaluate_circuit_sequentially(
    gates: &mut Vec<Gate>,
    wire_map: &mut HashMap<String, bool>,
    cycle: usize,
) {
    for gate in gates {
        debug_println!("evaluating gate: {:?}", gate);

        let input_values = gate.input_wires
            .iter()
            .map(|input| {
                match wire_map.get(input) {
                    Some(input_value) => *input_value,
                    None => panic!("Input {} not found in wire_map", input),
                }
            })
            .collect();

        let output_value = gate.evaluate(&input_values, cycle);
        wire_map.insert(gate.get_output_wire(), output_value);
    }
}

// Evaluate each gate in topological order
pub fn evaluate_circuit_parallel(
    level_map: &mut HashMap<usize, Vec<Gate>>,
    wire_map: &HashMap<String, bool>,
    cycle: usize,
) -> HashMap<String, bool> {
    let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = wire_map
        .iter()
        .enumerate()
        .map(|(i, (key, &value))| ((key, i), Arc::new(RwLock::new(value))))
        .unzip();

    // For each level
    for (_level, gates) in level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
        // debug_println!("\n{}) eval_values: {:?}", _level, eval_values);

        // Evaluate all the gates in the level in parallel
        gates.par_iter_mut().for_each(|gate| {
            let input_values: Vec<bool> = gate.input_wires
                .iter()
                .map(|input| {
                    // Get the corresponding index in the wires array
                    let index = match key_to_index.get(input) {
                        Some(&index) => index,
                        None => panic!("Input wire {} not found in key_to_index map", input),
                    };
                    // Read the value of the corresponding key
                    eval_values[index].read().unwrap().clone()
                })
                .collect();
            let output_value = gate.evaluate(&input_values, cycle);
            // debug_println!(" {:?} - gate: {:?}", thread::current().id(), gate);

            // Get the corresponding index in the wires array
            let output_index = key_to_index[&gate.get_output_wire()];

            // Update the value of the corresponding key
            *eval_values[output_index].write().unwrap() = output_value;
        });
    };

    key_to_index
        .iter()
        .map(|(&key, &index)| {
            (key.to_string(), eval_values[index].read().unwrap().clone())
        })
        .collect::<HashMap<String, bool>>()
}

// Evaluate each gate in topological order
pub fn evaluate_encrypted_circuit_parallel(
    server_key: &ServerKey,
    level_map: &mut HashMap<usize, Vec<Gate>>,
    enc_wire_map: &HashMap<String, Ciphertext>,
    cycle: usize,
) -> HashMap<String, Ciphertext> {
    let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
        .iter()
        .enumerate()
        .map(|(i, (key, value))| {
            ((key, i), Arc::new(RwLock::new(value.clone())))
        })
        .unzip();

    // For each level
    let total_levels = level_map.len();
    for (level, gates) in level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
        // debug_println!("\n{}) eval_values: {:?}", level, eval_values);

        // Evaluate all the gates in the level in parallel
        gates.par_iter_mut().for_each(|gate| {
            let input_values: Vec<Ciphertext> = gate.input_wires
                .iter()
                .map(|input| {
                    // Get the corresponding index in the wires array
                    let index = match key_to_index.get(input) {
                        Some(&index) => index,
                        None => panic!("Input wire {} not found in key_to_index map", input),
                    };

                    // Read the value of the corresponding key
                    eval_values[index].read().unwrap().clone()
                })
                .collect();
            let output_value = gate.evaluate_encrypted(server_key, &input_values, cycle);
            // debug_println!(" {:?} - gate: {:?}", thread::current().id(), gate);

            // Get the corresponding index in the wires array
            let output_index = key_to_index[&gate.get_output_wire()];

            // Update the value of the corresponding key
            *eval_values[output_index].write().unwrap() = output_value;
        });
        println!("  Evaluated gates in level [{}/{}]", level, total_levels);
    };

    key_to_index
        .iter()
        .map(|(&key, &index)| {
            (key.to_string(), eval_values[index].read().unwrap().clone())
        })
        .collect()
}

#[test]
fn test_gate_evaluation() {
    let (client_key, server_key) = gen_keys();

    let ptxts = vec![true, false];
    let ctxts = vec![client_key.encrypt(true), client_key.encrypt(false)];
    let gates = vec![
        Gate::new(
            String::from(""), 
            GateType::And, 
            vec![], 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Or, 
            vec![], 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Nor, 
            vec![], 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Xor, 
            vec![], 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Nand, 
            vec![], 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Not, 
            vec![], 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Xnor, 
            vec![], 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Mux, 
            vec![], 
            String::from(""), 
            0
        ),
    ];
    let mut rng = rand::thread_rng();
    for mut gate in gates {
        for i in 0..2 {
            for j in 0..2 {
                let mut inputs_ptxt = vec![ptxts[i], ptxts[i]];
                let mut inputs_ctxt = vec![ctxts[i].clone(), ctxts[j].clone()];
                if gate.gate_type == GateType::Mux {
                    let select: bool = rng.gen();
                    inputs_ptxt.push(select);
                    inputs_ctxt.push(client_key.encrypt(select));
                }
                let output_value_ptxt = gate.evaluate(&inputs_ptxt, 1);

                let output_value_enc = gate.evaluate_encrypted(
                    &server_key, &inputs_ctxt, 1
                );

                assert_eq!(output_value_ptxt, client_key.decrypt(&output_value_enc));
            }
        }
    }

}

#[test]
fn test_evaluate_circuit_parallel() {
    let (mut gates, mut wire_map, inputs, _, _) = 
        crate::verilog_parser::read_verilog_file("verilog-files/2bit_adder.v");

    let mut level_map = compute_levels(&mut gates, &inputs);
    for input_wire in &inputs {
        wire_map.insert(input_wire.to_string(), true);
    }
    wire_map = evaluate_circuit_parallel(&mut level_map, &wire_map, 1);

    assert_eq!(gates.len(), 10);
    assert_eq!(wire_map.len(), 15);
    assert_eq!(inputs.len(), 5);

    assert_eq!(wire_map["sum[0]"], true);
    assert_eq!(wire_map["sum[1]"], true);
    assert_eq!(wire_map["cout"], true);
    assert_eq!(wire_map["i0"], false);
    assert_eq!(wire_map["i1"], false);
}

#[test]
fn test_evaluate_encrypted_circuit_parallel() {
    let (mut gates, wire_map_im, inputs, _, _) = 
        crate::verilog_parser::read_verilog_file("verilog-files/2bit_adder.v");
    let mut ptxt_wire_map = wire_map_im.clone();

    let mut level_map = compute_levels(&mut gates, &inputs);
    
    // Plaintext
    for input_wire in &inputs {
        ptxt_wire_map.insert(input_wire.to_string(), true);
    }
    ptxt_wire_map = evaluate_circuit_parallel(&mut level_map, &ptxt_wire_map, 1);

    // Encrypted
    let (client_key, server_key) = gen_keys();

    let mut enc_wire_map = HashMap::new();
    for (wire, value) in wire_map_im {
        enc_wire_map.insert(wire, client_key.encrypt(value));
    }
    for input_wire in &inputs {
        enc_wire_map.insert(input_wire.to_string(), client_key.encrypt(true));
    }
    
    enc_wire_map = evaluate_encrypted_circuit_parallel(&server_key, &mut level_map, &enc_wire_map, 1);
    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(wire_name.to_string(), client_key.decrypt(&enc_wire_map[wire_name]));
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], dec_wire_map[key]);
    }
}
