use helm::verilog_parser::{read_input_wires, read_verilog_file};

#[test]
fn parse_two_bit_adder() {
    let (gates, wire_set, inputs, _, _, _, _) =
        read_verilog_file("hdl-benchmarks/processed-netlists/2-bit-adder.v", false);

    assert_eq!(gates.len(), 10);
    assert_eq!(wire_set.len(), 10);
    assert_eq!(inputs.len(), 5);
}

#[test]
fn input_wires_gates_parser() {
    let (_, _, inputs, _, _, _, _) =
        read_verilog_file("hdl-benchmarks/processed-netlists/2-bit-adder.v", false);

    let input_wires_map =
        read_input_wires("hdl-benchmarks/test-cases/2-bit-adder.inputs.csv", "bool");

    assert_eq!(input_wires_map.len(), inputs.len());
    for input_wire in inputs {
        assert!(input_wires_map.contains_key(&input_wire));
    }
}

#[test]
fn input_wires_arithmetic_parser() {
    let (_, _, inputs, _, _, _, _) = read_verilog_file(
        "hdl-benchmarks/processed-netlists/chi_squared_arith.v",
        true,
    );

    let input_wires_map = read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        "u32",
    );

    assert_eq!(input_wires_map.len(), inputs.len());
    for input_wire in inputs {
        assert!(input_wires_map.contains_key(&input_wire));
    }
}

// Check that it crashes if it contains both LUTs and arithmetic.
#[test]
#[should_panic(expected = "Can't mix LUTs with arithmetic operators!")]
fn invalid_arithmetic_with_luts_parser() {
    let (_, _, _, _, _, _, _) =
        read_verilog_file("hdl-benchmarks/processed-netlists/invalid.v", true);
}
