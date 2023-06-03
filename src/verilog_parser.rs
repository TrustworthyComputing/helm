use csv::Reader;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::gates::{Gate, GateType};

fn usize_to_bitvec(value: usize) -> Vec<u64> {
    let mut bits: Vec<u64> = Vec::new();

    for i in 0..64 {
        let bit = ((value >> i) & 1) as u64;
        bits.push(bit);
    }

    bits
}

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
        GateType::Not | GateType::Dff => (
            vec![String::from(name_and_inputs[1].trim())],
            String::from(tokens[2].trim_end_matches(';').trim_end_matches(')')),
        ),
        GateType::Mux | GateType::Lut => {
            let mut input_wires = vec![String::from(name_and_inputs[1])];
            for token in tokens.iter().take(tokens.len() - 1).skip(2) {
                input_wires.push(token.trim_end_matches(',').trim().to_owned());
            }
            let output_wire = String::from(
                tokens[tokens.len() - 1]
                    .trim_end_matches(';')
                    .trim_end_matches(')'),
            );
            (input_wires, output_wire)
        }
        _ => {
            let mut input_wires = vec![String::from(name_and_inputs[1])];
            input_wires.push(tokens[2].trim_end_matches(',').trim().to_owned());
            let output_wire = String::from(tokens[3].trim_end_matches(';').trim_end_matches(')'));
            (input_wires, output_wire)
        }
    };

    let lut_const = if gate_type == GateType::Lut {
        let lut_const_str = input_wires.remove(0);
        let lut_const_int = if lut_const_str.starts_with("0x") {
            Some(
                match usize::from_str_radix(&lut_const_str.trim_start_matches("0x"), 16) {
                    Ok(n) => n,
                    Err(_) => panic!("Failed to parse hex"),
                },
            )
        } else {
            Some(match lut_const_str.parse::<usize>() {
                Ok(n) => n,
                Err(_) => panic!("Failed to parse integer"),
            })
        };

        Some(usize_to_bitvec(lut_const_int.unwrap()))
    } else {
        None
    };

    Gate::new(
        gate_name,
        gate_type,
        input_wires,
        lut_const,
        output_wire,
        0,
    )
}

fn parse_range(range_str: &str) -> Option<(usize, usize)> {
    let trimmed = range_str.trim_matches(|c| c == '[' || c == ']');
    if let Some(tokens) = trimmed.split(':').collect::<Vec<_>>().get(..) {
        let first = tokens[0].parse::<usize>().ok()?;
        let second = tokens
            .get(1)
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(first);
        let start = std::cmp::min(first, second);
        let end = std::cmp::max(first, second);
        return Some((start, end));
    }

    None
}

pub fn read_verilog_file(
    file_name: &str,
) -> (
    HashSet<Gate>,
    HashMap<String, bool>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    bool,
    bool,
) {
    let file = File::open(file_name).expect("Failed to open file");
    let reader = BufReader::new(file);

    let mut is_sequential = false;
    let mut has_luts = false;
    let mut gates = HashSet::new();
    let mut wire_map = HashMap::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut _wires = Vec::new();
    let mut dff_outputs = Vec::new();
    for line in reader.lines() {
        let line = line.expect("Failed to read line").trim().to_owned();

        if line.is_empty()
            || line.starts_with("module")
            || line.starts_with("endmodule")
            || line.starts_with("//")
        {
            continue;
        }

        let tokens: Vec<&str> = line
            .split([',', ' '].as_ref())
            .filter(|s| !s.is_empty())
            .collect();
        match tokens[0] {
            "input" => {
                if let Some((start, end)) = parse_range(tokens[1]) {
                    let input_name = tokens[2].trim_matches(',').trim_end_matches(';');
                    inputs.extend((start..end + 1).map(|i| format!("{}[{}]", input_name, i)));
                } else {
                    inputs.extend(
                        tokens[1..]
                            .iter()
                            .map(|t| t.trim_matches(',').trim_end_matches(';').to_owned()),
                    );
                }
            }
            "output" => {
                if let Some((start, end)) = parse_range(tokens[1]) {
                    let output_name = tokens[2].trim_matches(',').trim_end_matches(';');
                    outputs.extend((start..end + 1).map(|i| format!("{}[{}]", output_name, i)));
                } else {
                    outputs.extend(
                        tokens[1..]
                            .iter()
                            .map(|t| t.trim_matches(',').trim_end_matches(';').to_owned()),
                    );
                }
            }
            "wire" => {
                for token in tokens.iter().skip(1) {
                    _wires.push(String::from(token.trim_matches(',').trim_end_matches(';')));
                }
            }
            _ => {
                // Gate
                let gate = parse_gate(&tokens);
                if gate.get_gate_type() == GateType::Dff {
                    is_sequential = true;
                    inputs.push(gate.get_output_wire());
                    dff_outputs.push(gate.get_output_wire());
                } else if gate.get_gate_type() == GateType::Lut {
                    has_luts = true;
                }

                wire_map.insert(gate.get_output_wire(), false);
                gates.insert(gate);
            }
        }
    }

    (
        gates,
        wire_map,
        inputs,
        outputs,
        dff_outputs,
        is_sequential,
        has_luts,
    )
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
                record[1].trim().to_string().parse::<bool>().unwrap(),
            )
        };

        input_map.insert(input_wire, init_value);
    }

    input_map
}

#[test]
fn test_parser() {
    let (gates, wire_map, inputs, _, _, _, _) = read_verilog_file(
        "hdl-benchmarks/processed-netlists/2-bit-adder.v"
    );

    assert_eq!(gates.len(), 10);
    assert_eq!(wire_map.len(), 10);
    assert_eq!(inputs.len(), 5);
}

#[test]
fn test_input_wires_parser() {
    let (_, _, inputs, _, _, _, _) = read_verilog_file(
        "hdl-benchmarks/processed-netlists/2-bit-adder.v"
    );

    let input_wires_map = read_input_wires(
        "hdl-benchmarks/test-cases/2-bit-adder.inputs.csv"
    );

    assert_eq!(input_wires_map.len(), inputs.len());
    for input_wire in inputs {
        assert!(input_wires_map.contains_key(&input_wire));
    }
}
