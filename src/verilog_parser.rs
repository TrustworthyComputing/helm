use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;

use crate::circuit::{Gate, GateType};

fn parse_gate(tokens: &[&str]) -> Gate {
    let gate_type = match tokens[0] {
        "and" => GateType::And,
        "or" => GateType::Or,
        "xor" => GateType::Xor,
        _ => panic!("Invalid gate type \"{}\"", tokens[0]),
    };

    let name_and_inputs = tokens[1]
        .split(|c| c == '(' || c == ',')
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<&str>>();
    let gate_name = String::from(name_and_inputs[0]);
    let mut input_wires: Vec<String> = name_and_inputs[1..]
        .iter()
        .map(|s| String::from(*s))
        .collect();
    input_wires.push(tokens[2].trim_end_matches(',').trim().to_owned());
    let output_wire = String::from(tokens[3].trim_end_matches(';').trim_end_matches(')'));
    Gate::new(gate_name, gate_type, input_wires, output_wire, 0)
}

fn parse_range(range_str: &str) -> Option<(usize, usize)> {
    let trimmed = range_str.trim_matches(|c| c == '[' || c == ']');
    if let Some(tokens) = trimmed.split(':').collect::<Vec<_>>().get(..) {
        let first = tokens[0].parse::<usize>().ok()?;
        let second = tokens.get(1).map(
            |t| t.parse::<usize>().ok()
        ).flatten().unwrap_or(first);
        let start = std::cmp::min(first, second);
        let end = std::cmp::max(first, second);
        return Some((start, end));
    }
    None
}

pub fn read_verilog_file(
    file_name: &str
) -> (Vec<Gate>, HashMap<String, bool>, Vec<String>) {
    let file = File::open(file_name).expect("Failed to open file");
    let reader = BufReader::new(file);

    let mut gates = Vec::new();
    let mut output_map = HashMap::new();
    let mut inputs = Vec::new();
    let mut _outputs = Vec::new();
    let mut _wires = Vec::new();
    for line in reader.lines() {
        let line = line.expect("Failed to read line").trim().to_owned();

        if line.is_empty() || line.starts_with("module") || 
            line.starts_with("endmodule") || line.starts_with("//") {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        match tokens[0] {
            "input" => {
                if let Some((start, end)) = parse_range(tokens[1]) {
                    let input_name = tokens[2].trim_matches(',').trim_end_matches(';');
                    inputs.extend((start..end+1).map(|i| format!("{}[{}]", input_name, i)));
                } else {
                    inputs.extend(tokens[1..].iter().map(|t| t.trim_matches(',').trim_end_matches(';').to_owned()));
                }
            },
            "output" => {
                if let Some((start, end)) = parse_range(tokens[1]) {
                    let output_name = tokens[2].trim_matches(',').trim_end_matches(';');
                    _outputs.extend((start..end+1).map(|i| format!("{}[{}]", output_name, i)));
                } else {
                    _outputs.extend(tokens[1..].iter().map(|t| t.trim_matches(',').trim_end_matches(';').to_owned()));
                }
            },
            "wire" => {
                for i in 1..tokens.len() {
                    _wires.push(String::from(
                        tokens[i].trim_matches(',').trim_end_matches(';')
                    ));
                }
            },
            _ => {
                let gate = parse_gate(&tokens);
                output_map.insert(gate.get_output_wire(), false);
                gates.push(gate);
            },
        }
    }

    (gates, output_map, inputs)
}
