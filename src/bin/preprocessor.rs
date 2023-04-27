use clap::{Arg, Command};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

#[cfg(test)]
use helm::verilog_parser;


fn parse_args() -> (String, String) {
    let matches = Command::new("HELM Preprocessor")
        .about("Preprocess Yosys outputs so that HELM can parse them")
        .arg(Arg::new("input")
            .long("input")
            .value_name("FILE")
            .help("Sets the input file to use")
            .required(true))
        .arg(Arg::new("output")
            .long("output")
            .value_name("FILE")
            .help("Sets the output file to use")
            .required(false))
        .get_matches();

    let in_file_name = matches.get_one::<String>("input").expect("required").to_owned();
    let out_file_name = {
        if matches.contains_id("output") {
            matches.get_one::<String>("output").unwrap().to_owned()
        } else {
            let mut out_file_name = in_file_name.to_owned();
            out_file_name.pop();
            out_file_name + "out.v"
        }
    };

    (in_file_name, out_file_name)
}

fn build_assign_dict(in_file_name: &String) -> HashMap<String, String> {
    let in_file = File::open(in_file_name).expect("Failed to open file");
    let reader = BufReader::new(in_file);
    let mut assign_dict = HashMap::new();
    let mut output_ports = HashSet::new();
    for line in reader.lines() {
        let line = line.expect("Failed to read line").trim().to_owned();

        if line.contains("output") {
            if line.contains("[") {
                output_ports.insert(line.split(' ').nth(2).unwrap().trim_end_matches(";").to_string());
            }
            else {
                output_ports.insert(line.split(' ').nth(1).unwrap().trim_end_matches(";").to_string());
            }
        } else if line.contains("assign") && !line.contains(">>") {
            let tokens: Vec<&str> = line.split(' ').collect();
            let output = tokens[1].trim_end_matches(";").trim_start_matches('_').trim_end_matches('_').to_string();
            let input = tokens[3].trim_end_matches(";").trim_start_matches('_').trim_end_matches('_').to_string();
            if output_ports.contains(&output.split('[').nth(0).unwrap().to_string()) {
                assign_dict.insert(input, output);
            } else {
                assign_dict.insert(output, input);
            }
        }
    }

    assign_dict
}


fn convert_verilog(
    in_file_name: &String,
    out_file_name: &String,
    wire_dict: &HashMap<String, String>
) {
    let in_file = File::open(in_file_name).expect("Failed to open file");
    let out_file = File::create(out_file_name).expect("Failed to create file");

    let reader = BufReader::new(in_file);
    let mut out_writer = BufWriter::new(out_file);
    let mut wires = Vec::new();
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    let mut multi_bit_inputs = Vec::new();
    let mut multi_bit_outputs = Vec::new();
    let mut gates = Vec::new();
    let mut lut_id = 1;
    let supported_gates = vec![
        "AND", "DFF", "MUX", "NAND", "NOR", "NOT", "OR", "XOR", "XNOR"
    ];

    let mut lines = reader.lines();
    loop {
        let line = lines.next();
        if line.is_none() {
            break;
        }
        let line = line.expect("Failed to read line").unwrap().trim().to_owned();
        if line.is_empty() || line.starts_with("//") || 
            line.starts_with("(*") || line.starts_with("/*")  {
            continue;
        }

        let tokens: Vec<&str> = line.split([',', ' '].as_ref()).filter(|s| !s.is_empty()).collect();
        match tokens[0] {
            "wire" => {
                for i in 1..tokens.len() {
                    wires.push(String::from(
                        tokens[i].trim_matches(',').trim_end_matches(';')
                            .trim_start_matches('_').trim_end_matches('_')
                    ));
                }
            },
            "input" => {
                if line.contains("[") {
                    multi_bit_inputs.push("  ".to_string() + &line.to_string());
                } else {
                    for i in 1..tokens.len() {
                        inputs.push(String::from(
                            tokens[i].trim_matches(',').trim_end_matches(';')
                        ));
                    }
                }
            },
            "output" => {
                if line.contains("[") {
                    multi_bit_outputs.push("  ".to_string() + &line.to_string());
                } else {
                    for i in 1..tokens.len() {
                        outputs.push(String::from(
                            tokens[i].trim_matches(',').trim_end_matches(';')
                        ));
                    }
                }
            },
            "assign" => { 
                if line.contains(">>") { // LUT
                    let mut lut_line = "lut ".to_owned();
                    lut_line += "lut_gate";
                    lut_line += &lut_id.to_string();
                    lut_line += "(";
                    lut_id += 1;
                    if line.contains('h') {
                        lut_line += "0x";
                    }
                    lut_line += tokens[3].split(['h', 'd']).filter(|s| !s.is_empty()).collect::<Vec<_>>()[1];
                    lut_line += ", ";
                    let mut curr_token = tokens[4];
                    let mut token_idx = 4;
                    loop {
                        if !curr_token.contains(">>") && !curr_token.contains("{") {
                            curr_token = curr_token.trim_start_matches('_').trim_end_matches(',');
                            curr_token = curr_token.trim_end_matches('_');
                            if wire_dict.contains_key(curr_token) {
                                lut_line += &wire_dict[curr_token];
                            } else {
                                lut_line += curr_token;
                            }
                            lut_line += ", ";
                        }
                        token_idx += 1;
                        curr_token = tokens[token_idx];
                        if curr_token.contains("};") { // end of lut statement
                            curr_token = tokens[1].trim_start_matches('_').trim_end_matches('_');
                            if wire_dict.contains_key(curr_token) {
                                lut_line += &wire_dict[curr_token];
                            } else {
                                lut_line += curr_token;
                            }
                            lut_line += ");";
                            break;
                        }
                    }
                    gates.push(lut_line.to_string());
                }
            },
            _ => { // Gate, module
                // If it's a gate
                if supported_gates.iter().any(|gate| line.contains(gate)) {
                    let is_dff = if line.contains("DFF") { true } else { false };
                    let mut gate_line = tokens[0][3..tokens[0].len()-1].to_lowercase();
                    if is_dff {
                        gate_line.truncate(gate_line.len() - 4);
                        lines.next();
                    }
                    gate_line += &(" g".to_owned() + tokens[1] + "(");
                    // Continue reading all inputs until you find a ');'
                    loop {
                        let line = lines.next();
                        if line.is_none() {
                            break;
                        }
                        let line = line.expect("Failed to read line").unwrap().trim().to_owned();
                        if line.starts_with(");") {
                            break;
                        } else {
                            let wire_name = line[
                                line.find("(").unwrap() + 1..line.find(")").unwrap()
                            ].trim_start_matches('_').trim_end_matches('_');

                            if wire_dict.contains_key(wire_name) {
                                gate_line += &wire_dict[wire_name];
                            } else {
                                gate_line += wire_name;
                            }
                            gate_line += ", ";
                        }
                    }
                    gate_line.pop(); gate_line.pop();
                    if is_dff { 
                        let mut parts: Vec<&str> = gate_line.split(',').collect();
                        parts.pop(); // remove the last element from the vector
                        gate_line = parts.join(","); // join the remaining elements with commas
                    }
                    gate_line += ");";
                    gates.push(gate_line.to_string());
                } else if line.starts_with("module") { // module or end_module
                    out_writer.write((line + "\n").as_bytes()).expect("Failed to write line");
                } 
            }
        }
    }

    // Write wires
    out_writer.write(b"  wire ").expect("Failed to write line");
    out_writer.write(wires.join(", ").as_bytes()).expect("Failed to write line");
    out_writer.write(b";\n").expect("Failed to write line");
    
    // Write inputs
    if !multi_bit_inputs.is_empty() {
        out_writer.write((multi_bit_inputs.join("\n")+"\n").as_bytes()).expect("Failed to write line");
    }
    if !inputs.is_empty() {
        out_writer.write(b"  input ").expect("Failed to write line");
        out_writer.write(inputs.join(", ").as_bytes()).expect("Failed to write line");
        out_writer.write(b";\n").expect("Failed to write line");
    }

    // Write outputs
    if !multi_bit_outputs.is_empty() {
        out_writer.write((multi_bit_outputs.join("\n")+"\n").as_bytes()).expect("Failed to write line");
    }
    if !outputs.is_empty() {
        out_writer.write(b"  output ").expect("Failed to write line");
        out_writer.write(outputs.join(", ").as_bytes()).expect("Failed to write line");
        out_writer.write(b";\n").expect("Failed to write line");
    }
    
    // Write gates
    for gate in gates {
        out_writer.write(("  ".to_owned() + &gate + "\n").as_bytes()).expect("Failed to write line");
    }

    out_writer.write(b"\nendmodule\n").expect("Failed to write line");
}

fn main() {
    let (in_file_name, out_file_name) = parse_args();

    let wire_dict = build_assign_dict(&in_file_name);
    convert_verilog(&in_file_name, &out_file_name, &wire_dict);
}

#[test]
fn test_preprocessor() {
    let in_file_name = String::from("verilog-files/s27.v");
    let out_file_name = String::from("verilog-files/s27.out.v");

    let wire_dict = build_assign_dict(&in_file_name);
    convert_verilog(&in_file_name, &out_file_name, &wire_dict);

    let (gates, wire_map, inputs, dff_outputs, is_sequential) = 
        verilog_parser::read_verilog_file("verilog-files/s27.out.v");

    assert_eq!(is_sequential, true);
    assert_eq!(gates.len(), 14);
    assert_eq!(wire_map.len(), 14);
    assert_eq!(inputs.len() - dff_outputs.len(), 6); // these are the true inputs

    let in_file_name = String::from("verilog-files/8bit-adder-lut.v");
    let out_file_name = String::from("verilog-files/8bit-adder-lut.out.v");

    let wire_dict = build_assign_dict(&in_file_name);
    convert_verilog(&in_file_name, &out_file_name, &wire_dict);

    let (gates, wire_map, inputs, dff_outputs, is_sequential) = 
        verilog_parser::read_verilog_file("verilog-files/8bit-adder-lut.out.v");

    assert_eq!(is_sequential, false);
// TODO
    println!("gates: {} {:?}", gates.len(), gates);
    println!("wire_map: {} {:?}", wire_map.len(), wire_map);
    println!("inputs: {} {:?}", inputs.len(), inputs);
    println!("dff_outputs: {} {:?}", dff_outputs.len(), dff_outputs);
    // assert_eq!(gates.len(), 14);
    // assert_eq!(wire_map.len(), 14);
    // assert_eq!(inputs.len() - dff_outputs.len(), 6); // these are the true inputs

}
