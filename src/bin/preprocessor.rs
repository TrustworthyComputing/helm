use clap::{Arg, Command};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::io::Write;
use std::collections::{HashMap, HashSet};

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

fn build_assign_dict(
    in_file_name: &String
) -> (HashMap<String, String>, HashSet<String>) {
    let in_file = File::open(in_file_name).expect("Failed to open file");
    let reader = BufReader::new(in_file);
    let mut assign_dict = HashMap::new();
    let mut output_ports = HashSet::new();
    for line in reader.lines() {
        let line = line.expect("Failed to read line").trim().to_owned();

        if line.contains("output") {
            output_ports.insert(line.split(' ').nth(1).unwrap().trim_end_matches(";").to_string());
        } else if line.contains("assign") {
            let tokens: Vec<&str> = line.split(' ').collect();
            let output = tokens[1].trim_end_matches(";").trim_start_matches('_').trim_end_matches('_').to_string();
            let input = tokens[3].trim_end_matches(";").trim_start_matches('_').trim_end_matches('_').to_string();
            if output_ports.contains(&output) {
                assign_dict.insert(input.clone(), output.clone());
            }
            assign_dict.insert(output, input);
        }
    }
    
    (assign_dict, output_ports)
}

fn main() {
    let (in_file_name, out_file_name) = parse_args();
    let file = File::open(&in_file_name).expect("Failed to open file");
    let out_file = File::create(out_file_name).expect("Failed to create file");

    let reader = BufReader::new(&file);
    let mut out_writer = BufWriter::new(out_file);
    let (wire_dict, outputs) = build_assign_dict(&in_file_name);
    
    // let mut wire_dict = HashMap::<String, String>::new();
    let mut wires = Vec::new();
    let mut inputs = Vec::new();
    let mut gates = Vec::new();
    let supported_gates = vec!["AND", "DFF", "MUX", "NAND", "NOR", "NOT", "OR", "XOR", "XNOR"];

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
                for i in 1..tokens.len() {
                    inputs.push(String::from(
                        tokens[i].trim_matches(',').trim_end_matches(';')
                    ));
                }
            },
            "output" | "assign" => {},
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
                                // println!("can't find {:?}", wire_name);
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
    out_writer.write(b"  input ").expect("Failed to write line");
    out_writer.write(inputs.join(", ").as_bytes()).expect("Failed to write line");
    out_writer.write(b";\n").expect("Failed to write line");

    // Write outputs
    out_writer.write(b"  output ").expect("Failed to write line");
    // out_writer.write(outputs.iter().join(", ").as_bytes()).expect("Failed to write line");
    out_writer.write(outputs.iter().cloned().collect::<Vec<_>>().join(", ").as_bytes()).expect("Failed to write line");
    out_writer.write(b";\n\n").expect("Failed to write line");
    
    // Write gates
    for gate in gates {
        out_writer.write(("  ".to_owned() + &gate + "\n").as_bytes()).expect("Failed to write line");
    }

    out_writer.write(b"\nendmodule\n").expect("Failed to write line");

}
