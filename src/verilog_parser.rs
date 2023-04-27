use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;
use csv::Reader;

use crate::circuit::{Gate, GateType};

fn parse_gate(tokens: &[&str]) -> Gate {
    let gate_type = match tokens[0] {
        "and" => GateType::And,
        "lut" => GateType::Lut,
        "dff" => GateType::Dff,
        "mux" => GateType::Mux,
        "nand" => GateType::Nand,
        "nor" => GateType::Nor,
        "not" => GateType::Not,
        "or" => GateType::Or,
        "xnor" => GateType::Xnor,
        "xor" => GateType::Xor,
        _ => panic!("Invalid gate type \"{}\"", tokens[0]),
    };

    let name_and_inputs = tokens[1]
        .split(|c| c == '(' || c == ',')
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<&str>>();
    let gate_name = String::from(name_and_inputs[0]);

    let (mut input_wires, output_wire) = match gate_type {
        GateType::Not | GateType::Dff => {
            (
                vec![String::from(name_and_inputs[1].trim())], 
                String::from(tokens[2].trim_end_matches(';').trim_end_matches(')'))
            )
        },
        GateType::Mux | GateType::Lut => {
            let mut input_wires = vec![String::from(name_and_inputs[1])];
            for i in 2..(tokens.len()-1) {
                input_wires.push(tokens[i].trim_end_matches(',').trim().to_owned());
            }
            let output_wire = String::from(tokens[tokens.len()-1].trim_end_matches(';').trim_end_matches(')'));
            (input_wires, output_wire)
        },
        _ => {
            let mut input_wires = vec![String::from(name_and_inputs[1])];
            input_wires.push(tokens[2].trim_end_matches(',').trim().to_owned());
            let output_wire = String::from(tokens[3].trim_end_matches(';').trim_end_matches(')'));
            (input_wires, output_wire)
        }
    };

    let mut lut_const: Option<usize> = None;
    if gate_type == GateType::Lut {
        let lut_const_str = input_wires.remove(0);
        if lut_const_str.starts_with("0x") {
            lut_const = Some(match usize::from_str_radix(&lut_const_str.trim_start_matches("0x"), 16) {
                Ok(n) => n,
                Err(_) => panic!("Failed to parse hex"),
            });
        } else {
            lut_const = Some(match lut_const_str.parse::<usize>() {
                Ok(n) => n,
                Err(_) => panic!("Failed to parse integer"),
            });
        }
    }
    Gate::new(gate_name, gate_type, input_wires, lut_const, output_wire, 0)
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
) -> (Vec<Gate>, HashMap<String, bool>, Vec<String>, Vec<String>, bool) {
    let file = File::open(file_name).expect("Failed to open file");
    let reader = BufReader::new(file);

    let mut is_sequential = false;
    let mut gates = Vec::new();
    let mut wire_map = HashMap::new();
    let mut inputs = Vec::new();
    let mut _outputs = Vec::new();
    let mut _wires = Vec::new();
    let mut dff_outputs = Vec::new();
    for line in reader.lines() {
        let line = line.expect("Failed to read line").trim().to_owned();

        if line.is_empty() || line.starts_with("module") || 
            line.starts_with("endmodule") || line.starts_with("//") {
            continue;
        }

        let tokens: Vec<&str> = line.split([',', ' '].as_ref()).filter(|s| !s.is_empty()).collect();
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
            _ => { // Gate
                let gate = parse_gate(&tokens);
                if gate.get_gate_type() == GateType::Dff {
                    is_sequential = true;
                    wire_map.insert(gate.get_output_wire(), false);
                    inputs.push(gate.get_output_wire());
                    dff_outputs.push(gate.get_output_wire());
                }
                wire_map.insert(gate.get_output_wire(), false);
                gates.push(gate);
            },
        }
    }

    (gates, wire_map, inputs, dff_outputs, is_sequential)
}

pub fn read_input_wires(file_name: &str) -> HashMap<String, bool> {
    let inputs_file = File::open(file_name).expect("Failed to open CSV file");
    let reader = BufReader::new(inputs_file);

    let mut input_map = HashMap::new();
    for rec in Reader::from_reader(reader).records() {
        let (input_wire, init_value): (String, bool) = {
            let record = rec.unwrap();
            assert_eq!(record.len(), 2);

            (
                record[0].trim().to_string(), 
                record[1].trim().to_string().parse::<bool>().unwrap()
            )
        };
        
        input_map.insert(input_wire, init_value);
    }

    input_map
}

#[test]
fn test_parser() {
    let (gates, wire_map, inputs, _, _) = 
        read_verilog_file("verilog-files/2bit_adder.v");

    assert_eq!(gates.len(), 10);
    assert_eq!(wire_map.len(), 10);
    assert_eq!(inputs.len(), 5);
}

#[test]
fn test_input_wires_parser() {
    let (_, _, inputs, _, _) = 
        read_verilog_file("verilog-files/2bit_adder.v");

    let input_wires_map = 
        read_input_wires("verilog-files/2bit_adder.input.csv");

    assert_eq!(input_wires_map.len(), inputs.len());
    for input_wire in inputs {
        assert!(input_wires_map.contains_key(&input_wire));
    }
}

