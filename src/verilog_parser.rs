use csv::Reader;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use termion::color;

use crate::gates::{Gate, GateType};
use crate::{parse_input_wire, PtxtType};

fn extract_const_val(input_str: &str) -> &str {
    let start_index = input_str.find('(').expect("Opening parenthesis not found");
    let end_index = input_str[start_index + 1..]
        .find(')')
        .expect("Closing parenthesis not found")
        + start_index
        + 1;
    &input_str[start_index + 1..end_index]
}

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
        "buf" => GateType::Buf,
        "czero" => GateType::ConstZero,
        "cone" => GateType::ConstOne,
        "add" => GateType::Add,
        "mult" => GateType::Mult,
        "div" => GateType::Div,
        "sub" => GateType::Sub,
        "shl" => GateType::Shl,
        "shr" => GateType::Shr,
        "copy" => GateType::Copy,
        _ => panic!("Invalid gate type \"{}\"", tokens[0]),
    };

    let name_and_inputs = tokens[1]
        .split(|c| c == '(' || c == ',')
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<&str>>();
    let gate_name = String::from(name_and_inputs[0]);

    let (mut input_wires, output_wire) = match gate_type {
        GateType::Not | GateType::Dff | GateType::Buf => (
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
        GateType::ConstOne | GateType::ConstZero => {
            let output_wire = String::from(extract_const_val(tokens[1]));
            (vec![], output_wire)
        }
        GateType::Copy => {
            let input_wires = vec![String::from(name_and_inputs[1])];
            let output_wire = String::from(tokens[2].trim_end_matches(';').trim_end_matches(')'));
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
                match usize::from_str_radix(lut_const_str.trim_start_matches("0x"), 16) {
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

    Gate::new(gate_name, gate_type, input_wires, lut_const, output_wire, 0)
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
    is_arith: bool,
) -> (
    HashSet<Gate>,
    HashSet<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    bool,
    bool,
) {
    let file = File::open(file_name).expect("Failed to open file");
    let reader = BufReader::new(file);

    let mut has_luts = false;
    let mut has_arith = false;
    let mut gates = HashSet::new();
    let mut wire_set = HashSet::new();
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
                    if is_arith {
                        inputs.extend(
                            tokens[2..]
                                .iter()
                                .map(|t| t.trim_matches(',').trim_end_matches(';').to_owned()),
                        );
                    } else {
                        inputs.extend((start..end + 1).map(|i| format!("{}[{}]", input_name, i)));
                    }
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
                    if is_arith {
                        outputs.extend(
                            tokens[2..]
                                .iter()
                                .map(|t| t.trim_matches(',').trim_end_matches(';').to_owned()),
                        );
                    } else {
                        outputs.extend((start..end + 1).map(|i| format!("{}[{}]", output_name, i)));
                    }
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
                    inputs.push(gate.get_output_wire());
                    dff_outputs.push(gate.get_output_wire());
                } else if gate.get_gate_type() == GateType::Lut {
                    has_luts = true;
                } else if gate.get_gate_type() == GateType::Add
                    || gate.get_gate_type() == GateType::Sub
                    || gate.get_gate_type() == GateType::Mult
                    || gate.get_gate_type() == GateType::Div
                    || gate.get_gate_type() == GateType::Shl
                    || gate.get_gate_type() == GateType::Shr
                    || gate.get_gate_type() == GateType::Copy
                {
                    has_arith = true;
                }

                wire_set.insert(gate.get_output_wire());

                gates.insert(gate);
            }
        }
    }

    if has_arith && gates.is_empty() {
        panic!(
            "{}[!]{} Parser error, no arithmetic gates detected.",
            color::Fg(color::LightRed),
            color::Fg(color::Reset)
        );
    } else if gates.is_empty() {
        panic!(
            "{}[!]{} Parser error, no gates detected. Make sure to use the \
                'no-expr' flag in Yosys.",
            color::Fg(color::LightRed),
            color::Fg(color::Reset)
        );
    }

    if has_arith && has_luts {
        panic!("Can't mix LUTs with arithmetic operators!");
    }

    (
        gates,
        wire_set,
        inputs,
        outputs,
        dff_outputs,
        has_luts,
        has_arith,
    )
}

pub fn read_input_wires(file_name: &str, ptxt_type: &str) -> HashMap<String, PtxtType> {
    let inputs_file = File::open(file_name).expect("Failed to open CSV file");
    let reader = BufReader::new(inputs_file);

    let mut input_map = HashMap::new();
    for rec in Reader::from_reader(reader).records() {
        let record = rec.unwrap();
        let wire_name = record[0].trim().to_string();

        if record.len() == 2 {
            let wire_value = parse_input_wire(&record[1].trim().to_string(), ptxt_type);
            input_map.insert(wire_name, wire_value);
        } else if record.len() == 3 && ptxt_type == "bool" {
            let wire_width = record[2].trim().parse::<usize>().unwrap();
            if wire_width > 1 {
                let bit_string = hex_to_bitstring(record[1].trim())
                    .chars()
                    .rev()
                    .collect::<Vec<_>>();
                for idx in 0..wire_width {
                    let key = wire_name.clone() + "[" + idx.to_string().as_str() + "]";
                    if idx < bit_string.len() {
                        input_map.insert(key, PtxtType::Bool(bit_string[idx] == '1'));
                    } else {
                        // pad with 0
                        input_map.insert(key, PtxtType::Bool(false));
                    }
                }
            } else {
                // if it's a bit.
                let wire_value = parse_input_wire(&record[1].trim().to_string(), ptxt_type);
                input_map.insert(wire_name, wire_value);
            }
        } else {
            panic!("The CSV should contain either two or three columns");
        }
    }

    input_map
}

pub fn write_output_wires(file_name: Option<String>, input_map: &HashMap<String, PtxtType>) {
    if let Some(file_name) = file_name {
        let file = File::create(&file_name).expect("Failed to create CSV file");
        let mut writer = BufWriter::new(file);

        for (input_wire, ptxt_type) in input_map.iter() {
            match ptxt_type {
                PtxtType::Bool(value) => {
                    writeln!(writer, "{}, {}", input_wire, value).expect("Failed to write record");
                }
                PtxtType::U8(value) => {
                    writeln!(writer, "{}, {}", input_wire, value).expect("Failed to write record");
                }
                PtxtType::U16(value) => {
                    writeln!(writer, "{}, {}", input_wire, value).expect("Failed to write record");
                }
                PtxtType::U32(value) => {
                    writeln!(writer, "{}, {}", input_wire, value).expect("Failed to write record");
                }
                PtxtType::U64(value) => {
                    writeln!(writer, "{}, {}", input_wire, value).expect("Failed to write record");
                }
                PtxtType::U128(value) => {
                    writeln!(writer, "{}, {}", input_wire, value).expect("Failed to write record");
                }
                PtxtType::None => unreachable!(),
            }
        }
        println!("Decrypted outputs written to {}", file_name);
    }
}

fn hex_to_bitstring(hex_string: &str) -> String {
    let mut bit_string = String::new();
    for hex_char in hex_string.chars() {
        match hex_char.to_digit(16) {
            Some(hex_digit) => {
                let binary_digit = format!("{:04b}", hex_digit);
                bit_string.push_str(&binary_digit);
            }
            None => unreachable!(),
        }
    }

    bit_string
}
