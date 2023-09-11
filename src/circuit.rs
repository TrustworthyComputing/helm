use crate::gates::{Gate, GateType};
use itertools::Itertools;
use rayon::prelude::*;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, RwLock},
    vec,
};
use termion::color;
use tfhe::{
    boolean::ciphertext::Ciphertext as CtxtBool,
    boolean::prelude::*,
    integer::{
        wopbs::WopbsKey as WopbsKeyInt, ClientKey as ClientKeyInt, ServerKey as ServerKeyInt,
    },
    prelude::*,
    set_server_key,
    shortint::{
        ciphertext::Ciphertext as CtxtShortInt, wopbs::WopbsKey as WopbsKeyShortInt,
        ClientKey as ClientKeyShortInt, ServerKey as ServerKeyShortInt,
    },
    unset_server_key, FheUint128, FheUint16, FheUint32, FheUint64, FheUint8,
};

use crate::{FheType, PtxtType};

pub trait EvalCircuit<C> {
    fn encrypt_inputs(
        &mut self,
        wire_set: &HashSet<String>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, C>;

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, C>,
        current_cycle: usize,
        ptxt_type: &str,
    ) -> HashMap<String, C>;

    fn decrypt_outputs(
        &self,
        enc_wire_map: &HashMap<String, C>,
        verbose: bool,
    ) -> HashMap<String, PtxtType>;
}

pub struct Circuit<'a> {
    gates: HashSet<Gate>,
    input_wires: &'a Vec<String>,
    output_wires: &'a Vec<String>,
    dff_outputs: &'a Vec<String>,
    ordered_gates: Vec<Gate>,
    level_map: HashMap<usize, Vec<Gate>>,
}

pub struct GateCircuit<'a> {
    circuit: Circuit<'a>,
    client_key: ClientKey,
    server_key: ServerKey,
}

pub struct LutCircuit<'a> {
    circuit: Circuit<'a>,
    client_key: ClientKeyShortInt,
    server_key: ServerKeyShortInt,
}

pub struct ArithCircuit<'a> {
    circuit: Circuit<'a>,
    server_key: tfhe::ServerKey,
    client_key: tfhe::ClientKey,
}

// Note: this is not used as there is no easy way to get LUTs with more than six inputs.
pub struct HighPrecisionLutCircuit<'a> {
    circuit: Circuit<'a>,
    wopbs_shortkey: WopbsKeyShortInt,
    wopbs_intkey: WopbsKeyInt,
    client_key: ClientKeyInt,
    server_intkey: ServerKeyInt,
}

fn is_numeric_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_digit())
}

impl<'a> Circuit<'a> {
    pub fn new(
        gates: HashSet<Gate>,
        input_wires: &'a Vec<String>,
        output_wires: &'a Vec<String>,
        dff_outputs: &'a Vec<String>,
    ) -> Circuit<'a> {
        Circuit {
            gates,
            input_wires,
            output_wires,
            dff_outputs,
            ordered_gates: Vec::new(),
            level_map: HashMap::new(),
        }
    }

    // Topologically sort the gates
    pub fn sort_circuit(&mut self) {
        assert!(!self.gates.is_empty());
        assert!(self.ordered_gates.is_empty());
        let mut wire_status = HashSet::new();
        self.input_wires.iter().for_each(|input| {
            wire_status.insert(input.clone());
        });

        let mut dff_level = Vec::new();
        let mut const_level = Vec::new();
        while !self.gates.is_empty() {
            // Temporary vector to store retained gates
            let mut level = Vec::new();
            let mut next_wire_status = HashSet::new();
            let mut ready = false;
            self.gates.retain(|gate| {
                if gate.get_gate_type() == GateType::Dff {
                    next_wire_status.insert(gate.get_output_wire());
                    dff_level.push(gate.clone());
                    ready = true;
                } else if gate.get_gate_type() == GateType::ConstOne
                    || gate.get_gate_type() == GateType::ConstZero
                {
                    next_wire_status.insert(gate.get_output_wire());
                    const_level.push(gate.clone());
                    ready = true;
                } else {
                    ready = gate
                        .get_input_wires()
                        .iter()
                        .all(|wire| wire_status.contains(wire) || wire.parse::<u32>().is_ok());
                    if ready {
                        next_wire_status.insert(gate.get_output_wire());
                        level.push(gate.clone());
                    }
                }
                !ready
            });

            wire_status.extend(next_wire_status);

            // Sort the gates (based on name) and add them to ordered_gates
            level.sort();
            self.ordered_gates.extend(level);
        }
        self.ordered_gates.extend(dff_level);
        // Remove all the gates after sorting is done. Use ordered_gates from
        // now on.
        self.gates.clear();
    }

    // Sort the gates by level so they can be evaluated later in parallel.
    pub fn compute_levels(&mut self) {
        // Make sure the sort circuit function has run.
        assert!(self.gates.is_empty());
        assert!(!self.ordered_gates.is_empty());
        // Initialization of input_wires to true
        let mut wire_levels = HashMap::new();
        for input in self.input_wires {
            wire_levels.insert(input.to_string(), 0);
        }
        for gate in &mut self.ordered_gates {
            if gate.get_gate_type() == GateType::Dff {
                match self.level_map.entry(std::usize::MAX) {
                    Entry::Vacant(e) => {
                        e.insert(vec![gate.clone()]);
                    }
                    Entry::Occupied(mut e) => {
                        e.get_mut().push(gate.clone());
                    }
                }
                gate.set_level(std::usize::MAX);
                continue;
            }
            // Find the max depth of the input wires
            let mut depth = 0;
            gate.get_input_wires().iter().for_each(|input| {
                let input_depth = match wire_levels.get(input) {
                    Some(value) => *value,
                    None => {
                        if input.parse::<u32>().is_ok() {
                            0
                        } else {
                            panic!("Input {} not found in wire_levels", input)
                        }
                    }
                };
                depth = std::cmp::max(depth, input_depth + 1);
            });

            gate.set_level(depth);
            match self.level_map.entry(depth) {
                Entry::Vacant(e) => {
                    e.insert(vec![gate.clone()]);
                }
                Entry::Occupied(mut e) => {
                    e.get_mut().push(gate.clone());
                }
            }

            wire_levels.insert(gate.get_output_wire(), depth);
        }

        // Move the DFFs in the correct key spot
        let total_keys = self.level_map.len();
        if let Some(values) = self.level_map.remove(&std::usize::MAX) {
            self.level_map.insert(total_keys, values);
        }
        if let Some(gate_vec) = self.level_map.get_mut(&total_keys) {
            for gate in gate_vec.iter_mut() {
                gate.set_level(total_keys);
            }
        }

        // Remove all the gates after the compute levels is done. Use
        // self.level_map from now on.
        self.ordered_gates.clear();
    }

    /// Initialize HashMap of all wires of the circuit.
    /// * inputs: initialize with values requested by client
    /// * intermediates: initialize to 0
    /// * outputs: initialize to 0
    pub fn initialize_wire_map(
        &self,
        wire_set: &HashSet<String>,
        user_inputs: &HashMap<String, PtxtType>,
        ptxt_type: &str,
    ) -> HashMap<String, PtxtType> {
        let mut wire_map = HashMap::new();
        // intermediate wires
        for key in wire_set.iter() {
            // wire_map.insert(key.clone(), PtxtType::Bool(false));
            wire_map.insert(key.clone(), PtxtType::None);
        }
        for input_wire in self.input_wires {
            // if no inputs are provided, initialize it to false
            if user_inputs.is_empty() {
                match ptxt_type {
                    "bool" => {
                        wire_map.insert(input_wire.to_string(), PtxtType::Bool(false));
                    }
                    "u8" => {
                        wire_map.insert(input_wire.to_string(), PtxtType::U8(0));
                    }
                    "u16" => {
                        wire_map.insert(input_wire.to_string(), PtxtType::U16(0));
                    }
                    "u32" => {
                        wire_map.insert(input_wire.to_string(), PtxtType::U32(0));
                    }
                    "u64" => {
                        wire_map.insert(input_wire.to_string(), PtxtType::U64(0));
                    }
                    "u128" => {
                        wire_map.insert(input_wire.to_string(), PtxtType::U128(0));
                    }
                    _ => unreachable!(),
                }
            } else if !user_inputs.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not in input wires!", input_wire);
            } else if let Some(user_value) = user_inputs.get(input_wire) {
                match ptxt_type {
                    "bool" => {
                        wire_map.insert(input_wire.to_string(), *user_value);
                    }
                    "u8" => {
                        wire_map.insert(input_wire.to_string(), *user_value);
                    }
                    "u16" => {
                        wire_map.insert(input_wire.to_string(), *user_value);
                    }
                    "u32" => {
                        wire_map.insert(input_wire.to_string(), *user_value);
                    }
                    "u64" => {
                        wire_map.insert(input_wire.to_string(), *user_value);
                    }
                    "u128" => {
                        wire_map.insert(input_wire.to_string(), *user_value);
                    }
                    _ => unreachable!(),
                }
            } else {
                panic!("\n Input wire \"{}\" not in input wires!", input_wire);
            }
        }
        for wire in self.dff_outputs {
            match ptxt_type {
                "bool" => {
                    wire_map.insert(wire.to_string(), PtxtType::Bool(false));
                }
                "u8" => {
                    wire_map.insert(wire.to_string(), PtxtType::U8(0));
                }
                "u16" => {
                    wire_map.insert(wire.to_string(), PtxtType::U16(0));
                }
                "u32" => {
                    wire_map.insert(wire.to_string(), PtxtType::U32(0));
                }
                "u64" => {
                    wire_map.insert(wire.to_string(), PtxtType::U64(0));
                }
                "u128" => {
                    wire_map.insert(wire.to_string(), PtxtType::U128(0));
                }
                _ => unreachable!(),
            }
        }
        wire_map
    }

    pub fn print_level_map(&self) {
        for level in self.level_map.keys().sorted() {
            println!("Level {}:", level);
            for gate in &self.level_map[level] {
                println!("  {:?}", gate);
            }
        }
    }

    pub fn get_ordered_gates(&self) -> &Vec<Gate> {
        &self.ordered_gates
    }

    pub fn evaluate(&mut self, wire_map: &HashMap<String, PtxtType>) -> HashMap<String, PtxtType> {
        // Make sure the sort circuit function has run.
        assert!(self.gates.is_empty());
        // Make sure the compute_levels function has run.
        assert!(self.ordered_gates.is_empty());

        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, &value))| ((key, i), Arc::new(RwLock::new(value))))
            .unzip();

        // For each level
        for (_level, gates) in self.level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<PtxtType> = gate
                    .get_input_wires()
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not in key_to_index", input),
                        };
                        // Read the value of the corresponding key
                        *eval_values[index].read().unwrap()
                    })
                    .collect();
                let output_value = gate.evaluate(&input_values);

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index]
                    .write()
                    .expect("Failed to acquire write lock") = output_value;
            });
        }

        key_to_index
            .iter()
            .map(|(&key, &index)| (key.to_string(), *eval_values[index].read().unwrap()))
            .collect::<HashMap<String, PtxtType>>()
    }
}

impl<'a> GateCircuit<'a> {
    pub fn new(client_key: ClientKey, server_key: ServerKey, circuit: Circuit) -> GateCircuit {
        GateCircuit {
            client_key,
            server_key,
            circuit,
        }
    }
}

impl<'a> LutCircuit<'a> {
    pub fn new(
        client_key: ClientKeyShortInt,
        server_key: ServerKeyShortInt,
        circuit: Circuit,
    ) -> LutCircuit {
        LutCircuit {
            client_key,
            server_key,
            circuit,
        }
    }
}

impl<'a> ArithCircuit<'a> {
    pub fn new(
        client_key: tfhe::ClientKey,
        server_key: tfhe::ServerKey,
        circuit: Circuit,
    ) -> ArithCircuit {
        ArithCircuit {
            client_key,
            server_key,
            circuit,
        }
    }
}

impl<'a> HighPrecisionLutCircuit<'a> {
    pub fn new(
        wopbs_shortkey: WopbsKeyShortInt,
        wopbs_intkey: WopbsKeyInt,
        client_key: ClientKeyInt,
        server_intkey: ServerKeyInt,
        circuit: Circuit,
    ) -> HighPrecisionLutCircuit {
        HighPrecisionLutCircuit {
            wopbs_shortkey,
            wopbs_intkey,
            client_key,
            server_intkey,
            circuit,
        }
    }
}

impl<'a> EvalCircuit<CtxtBool> for GateCircuit<'a> {
    fn encrypt_inputs(
        &mut self,
        wire_set: &HashSet<String>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, CtxtBool> {
        let mut enc_wire_map = wire_set
            .iter()
            .map(|wire| (wire.to_string(), self.server_key.trivial_encrypt(false)))
            .collect::<HashMap<_, _>>();

        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() || input_wire_map.contains_key("dummy") {
                enc_wire_map.insert(input_wire.to_string(), self.client_key.encrypt(false));
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not in input wires!", input_wire);
            } else {
                match input_wire_map[input_wire] {
                    PtxtType::Bool(v) => {
                        enc_wire_map.insert(input_wire.to_string(), self.client_key.encrypt(v));
                    }
                    _ => unreachable!(),
                }
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(false));
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, CtxtBool>,
        cycle: usize,
        _ptxt_type: &str,
    ) -> HashMap<String, CtxtBool> {
        // Make sure the sort circuit function has run.
        assert!(self.circuit.gates.is_empty());
        // Make sure the compute_levels function has run.
        assert!(self.circuit.ordered_gates.is_empty());

        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, value))| ((key, i), Arc::new(RwLock::new(value.clone()))))
            .unzip();

        // For each level
        let total_levels = self.circuit.level_map.len();
        for (level, gates) in self
            .circuit
            .level_map
            .iter_mut()
            .sorted_by_key(|(level, _)| *level)
        {
            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<CtxtBool> = gate
                    .get_input_wires()
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not in key_to_index map", input),
                        };

                        // Read the value of the corresponding key
                        eval_values[index].read().unwrap().clone()
                    })
                    .collect();
                let output_value = gate.evaluate_encrypted(&self.server_key, &input_values, cycle);

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index].write().unwrap() = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        key_to_index
            .iter()
            .map(|(&key, &index)| (key.to_string(), eval_values[index].read().unwrap().clone()))
            .collect()
    }

    fn decrypt_outputs(
        &self,
        enc_wire_map: &HashMap<String, CtxtBool>,
        verbose: bool,
    ) -> HashMap<String, PtxtType> {
        let mut decrypted_outputs = HashMap::new();
        for output_wire in self.circuit.output_wires {
            let decrypted_value = self.client_key.decrypt(&enc_wire_map[output_wire]);
            decrypted_outputs.insert(output_wire.clone(), PtxtType::Bool(decrypted_value));
        }

        for (i, (wire, val)) in decrypted_outputs.iter().sorted().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                println!(" {}: {}", wire, val);
            }
        }

        decrypted_outputs
    }
}

impl<'a> EvalCircuit<CtxtShortInt> for LutCircuit<'a> {
    fn encrypt_inputs(
        &mut self,
        wire_set: &HashSet<String>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, CtxtShortInt> {
        let mut enc_wire_map = wire_set
            .iter()
            .map(|wire| (wire.to_string(), self.server_key.create_trivial(0)))
            .collect::<HashMap<_, _>>();
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() || input_wire_map.contains_key("dummy") {
                enc_wire_map.insert(input_wire.to_string(), self.client_key.encrypt(0));
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                match input_wire_map[input_wire] {
                    PtxtType::Bool(v) => {
                        enc_wire_map
                            .insert(input_wire.to_string(), self.client_key.encrypt(v as u64));
                    }
                    _ => unreachable!(),
                }
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(0));
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, CtxtShortInt>,
        cycle: usize,
        _ptxt_type: &str,
    ) -> HashMap<String, CtxtShortInt> {
        // Make sure the sort circuit function has run.
        assert!(self.circuit.gates.is_empty());
        // Make sure the compute_levels function has run.
        assert!(self.circuit.ordered_gates.is_empty());

        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, value))| ((key, i), Arc::new(RwLock::new(value.clone()))))
            .unzip();

        // For each level
        let total_levels = self.circuit.level_map.len();
        for (level, gates) in self
            .circuit
            .level_map
            .iter_mut()
            .sorted_by_key(|(level, _)| *level)
        {
            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let mut input_values: Vec<CtxtShortInt> = gate
                    .get_input_wires()
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not in key_to_index map", input),
                        };

                        // Read the value of the corresponding key
                        eval_values[index].read().unwrap().clone()
                    })
                    .collect();
                let output_value = {
                    if gate.get_gate_type() == GateType::Lut {
                        gate.evaluate_encrypted_lut(&self.server_key, &mut input_values, cycle)
                    } else {
                        gate.evaluate_encrypted_dff(&input_values, cycle)
                    }
                };

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index]
                    .write()
                    .expect("Failed to acquire write lock") = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        key_to_index
            .iter()
            .map(|(&key, &index)| (key.to_string(), eval_values[index].read().unwrap().clone()))
            .collect()
    }

    fn decrypt_outputs(
        &self,
        enc_wire_map: &HashMap<String, CtxtShortInt>,
        verbose: bool,
    ) -> HashMap<String, PtxtType> {
        let mut decrypted_outputs = HashMap::new();
        for output_wire in self.circuit.output_wires {
            let decrypted_value = self.client_key.decrypt(&enc_wire_map[output_wire]);
            decrypted_outputs.insert(output_wire.clone(), PtxtType::U64(decrypted_value));
        }

        for (i, (wire, val)) in decrypted_outputs.iter().sorted().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                println!(" {}: {}", wire, val);
            }
        }

        decrypted_outputs
    }
}

impl<'a> EvalCircuit<FheType> for ArithCircuit<'a> {
    fn encrypt_inputs(
        &mut self,
        wire_set: &HashSet<String>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, FheType> {
        let ptxt_type = match input_wire_map.values().next().unwrap() {
            PtxtType::U8(_) => "u8",
            PtxtType::U16(_) => "u16",
            PtxtType::U32(_) => "u32",
            PtxtType::U64(_) => "u64",
            PtxtType::U128(_) => "u128",
            _ => unreachable!(),
        };
        let mut enc_wire_map = HashMap::<String, _>::new();
        for wire in wire_set {
            enc_wire_map.insert(wire.to_string(), FheType::None);
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() || input_wire_map.contains_key("dummy") {
                let encrypted_value = match ptxt_type {
                    "u8" => FheType::U8(FheUint8::try_encrypt(0, &self.client_key).unwrap()),
                    "u16" => FheType::U16(FheUint16::try_encrypt(0, &self.client_key).unwrap()),
                    "u32" => FheType::U32(FheUint32::try_encrypt(0, &self.client_key).unwrap()),
                    "u64" => FheType::U64(FheUint64::try_encrypt(0, &self.client_key).unwrap()),
                    "u128" => FheType::U128(FheUint128::try_encrypt(0, &self.client_key).unwrap()),
                    _ => unreachable!(),
                };

                enc_wire_map.insert(input_wire.to_string(), encrypted_value);
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                let encrypted_value = match input_wire_map[input_wire] {
                    PtxtType::U8(pt_val) => {
                        FheType::U8(FheUint8::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U16(pt_val) => {
                        FheType::U16(FheUint16::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U32(pt_val) => {
                        FheType::U32(FheUint32::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U64(pt_val) => {
                        FheType::U64(FheUint64::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U128(pt_val) => {
                        FheType::U128(FheUint128::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    _ => unreachable!(),
                };

                enc_wire_map.insert(input_wire.to_string(), encrypted_value);
            }
        }
        for wire in self.circuit.dff_outputs {
            let encrypted_value = match ptxt_type {
                "u8" => FheType::U8(FheUint8::try_encrypt(0, &self.client_key).unwrap()),
                "u16" => FheType::U16(FheUint16::try_encrypt(0, &self.client_key).unwrap()),
                "u32" => FheType::U32(FheUint32::try_encrypt(0, &self.client_key).unwrap()),
                "u64" => FheType::U64(FheUint64::try_encrypt(0, &self.client_key).unwrap()),
                "u128" => FheType::U128(FheUint128::try_encrypt(0, &self.client_key).unwrap()),
                _ => unreachable!(),
            };
            enc_wire_map.insert(wire.to_string(), encrypted_value);
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, FheType>,
        cycle: usize,
        ptxt_type: &str,
    ) -> HashMap<String, FheType> {
        // Make sure the sort circuit function has run.
        assert!(self.circuit.gates.is_empty());
        // Make sure the compute_levels function has run.
        assert!(self.circuit.ordered_gates.is_empty());

        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, value))| ((key, i), Arc::new(RwLock::new(value.clone()))))
            .unzip();

        set_server_key(self.server_key.clone());
        rayon::broadcast(|_| set_server_key(self.server_key.clone()));

        // For each level
        let total_levels = self.circuit.level_map.len();
        for (level, gates) in self
            .circuit
            .level_map
            .iter_mut()
            .sorted_by_key(|(level, _)| *level)
        {
            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let mut is_ptxt_op = false;
                // Identify if any of the input wires are constants
                for in_wire in gate.get_input_wires().iter() {
                    if is_numeric_string(in_wire) {
                        is_ptxt_op = true;
                    }
                }
                let output_value = {
                    if is_ptxt_op {
                        let mut ptxt_operand = PtxtType::None;
                        let mut ctxt_operand = FheType::None;
                        for in_wire in gate.get_input_wires().iter() {
                            if is_numeric_string(in_wire) {
                                ptxt_operand = match ptxt_type {
                                    "u8" => PtxtType::U8(in_wire.parse::<u8>().unwrap_or(0)),
                                    "u16" => PtxtType::U16(in_wire.parse::<u16>().unwrap_or(0)),
                                    "u32" => PtxtType::U32(in_wire.parse::<u32>().unwrap_or(0)),
                                    "u64" => PtxtType::U64(in_wire.parse::<u64>().unwrap_or(0)),
                                    "u128" => PtxtType::U128(in_wire.parse::<u128>().unwrap_or(0)),
                                    _ => unreachable!(),
                                };
                            } else {
                                let index = match key_to_index.get(in_wire) {
                                    Some(&index) => index,
                                    None => {
                                        panic!("Input wire {} not in key_to_index map", in_wire)
                                    }
                                };
                                // Read the value of the corresponding key
                                ctxt_operand = eval_values[index].read().unwrap().clone();
                            }
                        }
                        let ct_op = match ctxt_operand {
                            FheType::U8(_) => ctxt_operand,
                            FheType::U16(_) => ctxt_operand,
                            FheType::U32(_) => ctxt_operand,
                            FheType::U64(_) => ctxt_operand,
                            FheType::U128(_) => ctxt_operand,
                            _ => panic!("Empty ctxt operand!"),
                        };

                        if gate.get_gate_type() == GateType::Add {
                            gate.evaluate_encrypted_add_block_plain(&ct_op, ptxt_operand, cycle)
                        } else if gate.get_gate_type() == GateType::Sub {
                            gate.evaluate_encrypted_sub_block_plain(&ct_op, ptxt_operand, cycle)
                        } else if gate.get_gate_type() == GateType::Mult {
                            gate.evaluate_encrypted_mul_block_plain(&ct_op, ptxt_operand, cycle)
                        } else if gate.get_gate_type() == GateType::Div {
                            gate.evaluate_encrypted_div_block_plain(&ct_op, ptxt_operand, cycle)
                        } else if gate.get_gate_type() == GateType::Shl {
                            gate.evaluate_encrypted_shift_block_plain(
                                &ct_op,
                                ptxt_operand,
                                cycle,
                                true,
                            )
                        } else if gate.get_gate_type() == GateType::Shr {
                            gate.evaluate_encrypted_shift_block_plain(
                                &ct_op,
                                ptxt_operand,
                                cycle,
                                false,
                            )
                        } else {
                            unreachable!();
                        }
                    } else {
                        let input_values: Vec<FheType> = gate
                            .get_input_wires()
                            .iter()
                            .map(|input| {
                                // Get the corresponding index in the wires array
                                let index = match key_to_index.get(input) {
                                    Some(&index) => index,
                                    None => panic!("Input wire {} not in key_to_index map", input),
                                };

                                // Read the value of the corresponding key
                                eval_values[index].read().unwrap().clone()
                            })
                            .collect();

                        if gate.get_gate_type() == GateType::Add {
                            gate.evaluate_encrypted_add_block(
                                &input_values[0],
                                &input_values[1],
                                cycle,
                            )
                        } else if gate.get_gate_type() == GateType::Sub {
                            gate.evaluate_encrypted_sub_block(
                                &input_values[0],
                                &input_values[1],
                                cycle,
                            )
                        } else if gate.get_gate_type() == GateType::Div {
                            gate.evaluate_encrypted_div_block(
                                &input_values[0],
                                &input_values[1],
                                cycle,
                            )
                        } else if gate.get_gate_type() == GateType::Shl {
                            gate.evaluate_encrypted_shift_block(
                                &input_values[0],
                                &input_values[1],
                                cycle,
                                true,
                            )
                        } else if gate.get_gate_type() == GateType::Shr {
                            gate.evaluate_encrypted_shift_block(
                                &input_values[0],
                                &input_values[1],
                                cycle,
                                false,
                            )
                        } else if gate.get_gate_type() == GateType::Copy {
                            gate.evaluate_encrypted_copy_block(&input_values[0], cycle)
                        } else {
                            gate.evaluate_encrypted_mul_block(
                                &input_values[0],
                                &input_values[1],
                                cycle,
                            )
                        }
                    }
                };

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index]
                    .write()
                    .expect("Failed to acquire write lock") = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        rayon::broadcast(|_| unset_server_key());
        unset_server_key();

        key_to_index
            .iter()
            .map(|(&key, &index)| (key.to_string(), eval_values[index].read().unwrap().clone()))
            .collect()
    }

    fn decrypt_outputs(
        &self,
        enc_wire_map: &HashMap<String, FheType>,
        verbose: bool,
    ) -> HashMap<String, PtxtType> {
        let mut decrypted_outputs = HashMap::new();

        for output_wire in self.circuit.output_wires {
            let decrypted = enc_wire_map[output_wire].decrypt(&self.client_key);
            decrypted_outputs.insert(output_wire.clone(), decrypted);
        }

        for (i, (wire, val)) in decrypted_outputs.iter().sorted().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                println!(" {}: {}", wire, val);
            }
        }

        decrypted_outputs
    }
}

impl<'a> EvalCircuit<CtxtShortInt> for HighPrecisionLutCircuit<'a> {
    fn encrypt_inputs(
        &mut self,
        wire_set: &HashSet<String>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, CtxtShortInt> {
        let mut enc_wire_map = wire_set
            .iter()
            .map(|wire| (wire.to_string(), self.client_key.encrypt_one_block(0u64)))
            .collect::<HashMap<_, _>>();
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() || input_wire_map.contains_key("dummy") {
                enc_wire_map.insert(input_wire.to_string(), self.client_key.encrypt_one_block(0));
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                match input_wire_map[input_wire] {
                    PtxtType::Bool(v) => {
                        enc_wire_map.insert(
                            input_wire.to_string(),
                            self.client_key.encrypt_one_block(v as u64),
                        );
                    }
                    _ => unreachable!(),
                }
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt_one_block(0));
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, CtxtShortInt>,
        cycle: usize,
        _ptxt_type: &str,
    ) -> HashMap<String, CtxtShortInt> {
        // Make sure the sort circuit function has run.
        assert!(self.circuit.gates.is_empty());
        // Make sure the compute_levels function has run.
        assert!(self.circuit.ordered_gates.is_empty());

        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, value))| ((key, i), Arc::new(RwLock::new(value.clone()))))
            .unzip();

        // For each level
        let total_levels = self.circuit.level_map.len();
        for (level, gates) in self
            .circuit
            .level_map
            .iter_mut()
            .sorted_by_key(|(level, _)| *level)
        {
            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<CtxtShortInt> = gate
                    .get_input_wires()
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not in key_to_index map", input),
                        };

                        // Read the value of the corresponding key
                        eval_values[index].read().unwrap().clone()
                    })
                    .collect();
                let output_value = gate.evaluate_encrypted_high_precision_lut(
                    &self.wopbs_shortkey,
                    &self.wopbs_intkey,
                    &self.server_intkey,
                    &input_values,
                    cycle,
                );

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index]
                    .write()
                    .expect("Failed to acquire write lock") = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        key_to_index
            .iter()
            .map(|(&key, &index)| (key.to_string(), eval_values[index].read().unwrap().clone()))
            .collect()
    }

    fn decrypt_outputs(
        &self,
        enc_wire_map: &HashMap<String, CtxtShortInt>,
        verbose: bool,
    ) -> HashMap<String, PtxtType> {
        let mut decrypted_outputs = HashMap::new();

        for output_wire in self.circuit.output_wires {
            let decrypted = self
                .client_key
                .decrypt_one_block(&enc_wire_map[output_wire]);
            decrypted_outputs.insert(output_wire.clone(), PtxtType::U64(decrypted));
        }

        for (i, (wire, val)) in decrypted_outputs.iter().sorted().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                println!(" {}: {}", wire, val);
            }
        }

        decrypted_outputs
    }
}
