use helm::verilog_parser::{read_input_wires, read_verilog_file};
use helm::PtxtType;

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

/// Check that it crashes if it contains both LUTs and arithmetic.
#[test]
#[should_panic(expected = "Can't mix LUTs with arithmetic operators!")]
fn invalid_arithmetic_with_luts_parser() {
    let (_, _, _, _, _, _, _) =
        read_verilog_file("hdl-benchmarks/processed-netlists/invalid.v", true);
}

/// Test get_input_wire_map with true, false, 0, 1 for bool.
///     wire, value
///     a[0], true
///     a[1], 0
///     b[0], false
///     b[1], 1
///     cin, false
#[test]
fn bool_input_wires() {
    let wire_map = read_input_wires("./hdl-benchmarks/test-cases/2-bit-adder.inputs.csv", "bool");

    assert_eq!(wire_map["a[0]"], PtxtType::Bool(true));
    assert_eq!(wire_map["a[1]"], PtxtType::Bool(false));
    assert_eq!(wire_map["b[0]"], PtxtType::Bool(false));
    assert_eq!(wire_map["b[1]"], PtxtType::Bool(true));
    assert_eq!(wire_map["cin"], PtxtType::Bool(false));
}

/// Test get_input_wire_map with integer.
///     wire, value
///     N0, 2
///     N1, 7
///     N2, 9
#[test]
fn integer_input_wires() {
    let wire_map = read_input_wires(
        "./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        "u8",
    );
    assert_eq!(wire_map["N0"], PtxtType::U8(2));
    assert_eq!(wire_map["N1"], PtxtType::U8(7));
    assert_eq!(wire_map["N2"], PtxtType::U8(9));

    let wire_map = read_input_wires(
        "./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        "u16",
    );
    assert_eq!(wire_map["N0"], PtxtType::U16(2));
    assert_eq!(wire_map["N1"], PtxtType::U16(7));
    assert_eq!(wire_map["N2"], PtxtType::U16(9));

    let wire_map = read_input_wires(
        "./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        "u32",
    );
    assert_eq!(wire_map["N0"], PtxtType::U32(2));
    assert_eq!(wire_map["N1"], PtxtType::U32(7));
    assert_eq!(wire_map["N2"], PtxtType::U32(9));

    let wire_map = read_input_wires(
        "./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        "u64",
    );
    assert_eq!(wire_map["N0"], PtxtType::U64(2));
    assert_eq!(wire_map["N1"], PtxtType::U64(7));
    assert_eq!(wire_map["N2"], PtxtType::U64(9));

    let wire_map = read_input_wires(
        "./hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        "u128",
    );
    assert_eq!(wire_map["N0"], PtxtType::U128(2));
    assert_eq!(wire_map["N1"], PtxtType::U128(7));
    assert_eq!(wire_map["N2"], PtxtType::U128(9));
}

// TODO:
/// Test get_input_wire_map with int for bits (AES example).
#[test]
fn bool_input_wires_array_as_int() {}
