mod circuit;
mod verilog_parser;

fn main() {
    let (gates, mut output_map, inputs, outputs, wires) = verilog_parser::read_verilog_file("verilog-files/2bit_adder.v");

    println!();
    println!("inputs: {:?}", inputs);
    println!("outputs: {:?}", outputs);
    println!("wires: {:?}", wires);
    println!("output_map");
    for out in &output_map {
        println!(" {:?}", out);
    }
    println!();
    
    // Initialization of inputs to true
    for input in &inputs {
        output_map.insert(input.to_string(), (true, 0));
    }

    let level_map = circuit::evaluate_circuit(gates, &mut output_map);
    for level in &level_map {
        println!(" {:?}", level);
    }

    for (wire_name, output) in output_map {
        println!("Wire: {}: {}", wire_name, output.0);
    }
}
