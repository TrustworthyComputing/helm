use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use rayon::prelude::*;


#[derive(Debug, Eq, PartialEq, Hash)]
enum GateType {
    And,
    Or,
    Xor,
}

#[derive(Debug, Eq, PartialEq, Hash)]
struct Gate {
    gate_name: String,
    gate_type: GateType,
    input_wires: Vec<String>,
    output_wire: String,
    output: Option<bool>,
}

impl Gate {
    fn new(gate_name: String, gate_type: GateType, input_wires: Vec<String>, output_wire: String) -> Self {
        Gate {
            gate_name,
            gate_type,
            input_wires,
            output_wire,
            output: None,
        }
    }

    fn evaluate(&mut self, input_map: &HashMap<String, bool>) -> bool {
        if let Some(output) = self.output {
            return output;
        }

        let input_values: Vec<bool> = self.input_wires.iter().map(|input| input_map[input]).collect();
        let output = match self.gate_type {
            GateType::And => input_values.iter().all(|&v| v),
            GateType::Or => input_values.iter().any(|&v| v),
            GateType::Xor => input_values.iter().filter(|&&v| v).count() % 2 == 1,
        };

        self.output = Some(output);
        output
    }
}

fn read_verilog_file(file_name: &str) -> (Vec<Gate>, HashMap<String, bool>) {
    let file = File::open(file_name).expect("Failed to open file");
    let reader = BufReader::new(file);

    let mut gates = Vec::new();
    let mut output_map = HashMap::new();

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let tokens: Vec<&str> = line.split("//").next().unwrap().trim().split(' ').collect();

        let gate_name = String::from(tokens[0]);
        let output_wire = String::from(tokens[1]);
        let gate_type = match tokens[2] {
            "and" => GateType::And,
            "or" => GateType::Or,
            "xor" => GateType::Xor,
            _ => panic!("Invalid gate type"),
        };
        let input_wires: Vec<String> = tokens[3..].iter().map(|&s| String::from(s)).collect();
        let gate = Gate::new(gate_name, gate_type, input_wires, output_wire.clone());
        gates.push(gate);

        output_map.insert(output_wire, false); // default output value before evaluation
    }

    (gates, output_map)
}

// Evaluate each gate in topological order
fn evaluate_circuit(gates: Vec<Gate>, output_map: &mut HashMap<String, bool>) {
    for gate in gates {
        let input_map: HashMap<String, bool> = gate
            .input_wires
            .iter()
            .map(|input| {
                let input_value = match output_map.get(input) {
                    Some(value) => *value,
                    None => panic!("Input {} not found in output map", input),
                };
                (input.clone(), input_value)
            })
            .collect();

        let mut gate = gate; // make mutable copy for evaluation
        let output_value = gate.evaluate(&input_map);
        output_map.insert(gate.output_wire, output_value);
    }

}

fn main() {
    let (gates, mut output_map) = read_verilog_file("verilog-files/example.v");

    for gate in &gates {
        println!("gate: {:?}", gate);
    }
    
    // Initialization
    output_map.insert(String::from("b"), true);
    output_map.insert(String::from("c"), true);
    output_map.insert(String::from("e"), false);
    output_map.insert(String::from("g"), false);

    evaluate_circuit(gates, &mut output_map);
   
    for (gate_name, output) in output_map {
        println!("Gate: {}, Output: {}", gate_name, output);
    }
}
