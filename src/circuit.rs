use itertools::Itertools;
use std::collections::{HashMap, hash_map::Entry};
use debug_print::debug_println;
use std::vec;
use std::sync::{Arc, Mutex};
use rayon::prelude::*;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum GateType {
    And,
    Or,
    Xor,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Gate {
    gate_name: String,
    gate_type: GateType,
    input_wires: Vec<String>,
    output_wire: String,
    output: Option<bool>,
    level: usize,
}

impl Gate {
    pub fn new(
        gate_name: String, 
        gate_type: GateType,
        input_wires: Vec<String>,
        output_wire: String,
        level: usize
    ) -> Self {
        Gate {
            gate_name,
            gate_type,
            input_wires,
            output_wire,
            level,
            output: None,
        }
    }
    
    pub fn get_output_wire(&self) -> String {
        self.output_wire.clone()
    }

    fn evaluate(&mut self, input_map: &HashMap<String, bool>) -> bool {
        if let Some(output) = self.output {
            return output;
        }
        let input_values: Vec<bool> = self.input_wires
            .iter().map(|input| input_map[input]).collect();
        let output = match self.gate_type {
            GateType::And => input_values.iter().all(|&v| v),
            GateType::Or => input_values.iter().any(|&v| v),
            GateType::Xor => input_values.iter().filter(|&&v| v).count() % 2 == 1,
        };

        self.output = Some(output);
        output
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
    output_map: &mut HashMap<String, bool>
) {
    for gate in gates {
        debug_println!("evaluating gate: {:?}", gate);

        let input_map: HashMap<String, bool> = gate.input_wires
            .iter()
            .map(|input| {
                let input_value = match output_map.get(input) {
                    Some(value) => *value,
                    None => panic!("Input {} not found in output map", input),
                };
                (input.clone(), input_value)
            })
            .collect();

        let output_value = gate.evaluate(&input_map);
        output_map.insert(gate.get_output_wire(), output_value);
    }
}

// Evaluate each gate in topological order
pub fn evaluate_circuit_parallel(
    level_map: &mut HashMap<usize, Vec<Gate>>,
    output_map: &mut HashMap<String, bool>,
) {
    let output_map = Arc::new(Mutex::new(output_map));
    for (_, gates) in level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
        gates.par_iter_mut().for_each(|gate| {
            debug_println!("evaluating gate: {:?}", gate);
            let input_map: HashMap<String, bool> = gate.input_wires
                .iter()
                .map(|input| {
                    let input_value = match output_map.lock().unwrap().get(input) {
                        Some(value) => *value,
                        None => panic!("Input {} not found in output map", input),
                    };
                    (input.clone(), input_value)
                })
                .collect();

            let output_value = gate.evaluate(&input_map);
            output_map.lock().unwrap().insert(
                gate.get_output_wire().to_owned(), output_value
            );
        });
    }
}

