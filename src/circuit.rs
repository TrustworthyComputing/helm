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

#[derive(Clone, Debug)]
pub enum GateType {
    And,
    Or,
    Mux,
    Nand,
    Not,
    Xor,
}

#[derive(Clone, Debug)]
pub struct Gate {
    _gate_name: String,
    gate_type: GateType,
    input_wires: Vec<String>,
    output_wire: String,
    level: usize,
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
            output: None,
            encrypted_output: None,
        }
    }
    
    pub fn get_output_wire(&self) -> String {
        self.output_wire.clone()
    }

    fn evaluate(&mut self, input_values: &Vec<bool>) -> bool {
        if let Some(output) = self.output {
            return output;
        }
        let output = match self.gate_type {
            GateType::And => input_values.iter().all(|&v| v),
            GateType::Or => input_values.iter().any(|&v| v),
            GateType::Xor => input_values.iter().filter(|&&v| v).count() % 2 == 1,
            GateType::Not => !input_values[0],
            GateType::Nand => !input_values.iter().all(|&v| v),
            GateType::Mux => {
                let select_bit = input_values[2];
                (select_bit && input_values[0]) || (!select_bit && input_values[1])
            },
        };

        self.output = Some(output);
        output
    }

    fn evaluate_encrypted(
        &mut self, 
        server_key: &ServerKey,
        input_values: &Vec<Ciphertext>
    ) -> Ciphertext {
        if let Some(encrypted_output) = self.encrypted_output.clone() {
            return encrypted_output;
        }
        let encrypted_output = match self.gate_type {
            GateType::And => server_key.
                and(&input_values[0], &input_values[1]),
            GateType::Or => server_key.
                or(&input_values[0], &input_values[1]),
            GateType::Xor => server_key.
                xor(&input_values[0], &input_values[1]),
            GateType::Not => server_key.
                not(&input_values[0]),
            GateType::Nand => server_key.
                nand(&input_values[0], &input_values[1]),
            GateType::Mux => server_key.
                mux(&input_values[2], &input_values[0],
                    &input_values[1]),
        };

        self.encrypted_output = Some(encrypted_output.clone());
        encrypted_output
    }
}

// Sort the gates by level so they can be evaluated later in parallel.
pub fn compute_levels(
    gates: &mut Vec<Gate>, wire_levels: &mut HashMap<String, usize>
) -> HashMap::<usize, Vec<Gate>> {
    let mut level_map = HashMap::new();
    for mut gate in gates {
        // Find the max depth of the input wires
        let mut depth = 0;
        gate.input_wires.iter().for_each(|input| {
            let input_depth = match wire_levels.get(input) {
                Some(value) => *value,
                None => panic!("Input {} not found in output map", input),
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
    wire_map: &mut HashMap<String, bool>
) {
    for gate in gates {
        debug_println!("evaluating gate: {:?}", gate);

        let input_values = gate.input_wires
            .iter()
            .map(|input| {
                match wire_map.get(input) {
                    Some(input_value) => *input_value,
                    None => panic!("Input {} not found in output map", input),
                }
            })
            .collect();

        let output_value = gate.evaluate(&input_values);
        wire_map.insert(gate.get_output_wire(), output_value);
    }
}

// Evaluate each gate in topological order
pub fn evaluate_circuit_parallel(
    level_map: &mut HashMap<usize, Vec<Gate>>,
    wire_map: &HashMap<String, bool>,
) -> HashMap<String, bool> {
    let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = wire_map
        .iter()
        .enumerate()
        .map(|(i, (key, &value))| ((key, i), Arc::new(RwLock::new(value))))
        .unzip();

    // For each level
    for (_level, gates) in level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
        debug_println!("\n{}) eval_values: {:?}", _level, eval_values);

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
            let output_value = gate.evaluate(&input_values);
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
            let output_value = gate.evaluate_encrypted(server_key, &input_values);
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
