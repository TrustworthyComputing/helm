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

#[cfg(test)]
use debug_print::debug_println;
#[cfg(test)]
use rand::Rng;
#[cfg(test)]
use tfhe::shortint::parameters::{
    parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_1_CARRY_1,
    PARAM_MESSAGE_3_CARRY_0,
};
#[cfg(test)]
use tfhe::{generate_keys, ConfigBuilder};

use crate::{FheType, PtxtType};

pub trait EvalCircuit<C> {
    fn encrypt_inputs(
        &mut self,
        wire_map_im: &HashMap<String, PtxtType>,
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

    pub fn initialize_wire_map(
        &self,
        wire_map_im: &HashMap<String, PtxtType>,
        user_inputs: &HashMap<String, PtxtType>,
        ptxt_type: &str,
    ) -> HashMap<String, PtxtType> {
        let mut wire_map = HashMap::new();
        for (key, value) in wire_map_im.iter() {
            wire_map.insert(key.clone(), *value);
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
        wire_map_im: &HashMap<String, PtxtType>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, CtxtBool> {
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            match value {
                PtxtType::Bool(v) => {
                    enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(v));
                }
                _ => unreachable!(),
            }
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
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

        for (i, (wire, val)) in decrypted_outputs.iter().enumerate() {
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
        wire_map_im: &HashMap<String, PtxtType>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, CtxtShortInt> {
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            match value {
                PtxtType::Bool(v) => {
                    enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(v as u64));
                }
                _ => unreachable!(),
            }
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
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
                let output_value = {
                    if gate.get_gate_type() == GateType::Lut {
                        gate.evaluate_encrypted_lut(&self.server_key, &input_values, cycle)
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

        for (i, (wire, val)) in decrypted_outputs.iter().enumerate() {
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
        wire_map_im: &HashMap<String, PtxtType>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, FheType> {
        let mut ptxt_type = "u32";
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            if !is_numeric_string(wire) {
                let encrypted_value = match value {
                    PtxtType::U8(pt_val) => {
                        ptxt_type = "u8";
                        FheType::U8(FheUint8::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U16(pt_val) => {
                        ptxt_type = "u16";
                        FheType::U16(FheUint16::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U32(pt_val) => {
                        ptxt_type = "u32";
                        FheType::U32(FheUint32::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U64(pt_val) => {
                        ptxt_type = "u64";
                        FheType::U64(FheUint64::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    PtxtType::U128(pt_val) => {
                        ptxt_type = "u128";
                        FheType::U128(FheUint128::try_encrypt(pt_val, &self.client_key).unwrap())
                    }
                    _ => unreachable!(),
                };
                enc_wire_map.insert(wire.to_string(), encrypted_value);
            }
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
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

        for (i, (wire, val)) in decrypted_outputs.iter().enumerate() {
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
        wire_map_im: &HashMap<String, PtxtType>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, CtxtShortInt> {
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            match value {
                PtxtType::Bool(v) => {
                    enc_wire_map.insert(
                        wire.to_string(),
                        self.client_key.encrypt_one_block(v as u64),
                    );
                }
                _ => unreachable!(),
            }
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
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

        for (i, (wire, val)) in decrypted_outputs.iter().enumerate() {
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

#[test]
fn test_gate_evaluation() {
    let (client_key, server_key) = gen_keys();

    let ptxts = vec![PtxtType::Bool(true), PtxtType::Bool(false)];
    let ctxts = vec![client_key.encrypt(true), client_key.encrypt(false)];
    let gates = vec![
        Gate::new(
            String::from(""),
            GateType::And,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Or,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Nor,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Xor,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Nand,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Not,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Xnor,
            vec![],
            None,
            "".to_string(),
            0,
        ),
        Gate::new(
            String::from(""),
            GateType::Mux,
            vec![],
            None,
            "".to_string(),
            0,
        ),
    ];
    let mut rng = rand::thread_rng();
    let mut cycle = 1;
    for mut gate in gates {
        for i in 0..2 {
            for j in 0..2 {
                let mut inputs_ptxt = vec![ptxts[i], ptxts[j]];
                let mut inputs_ctxt = vec![ctxts[i].clone(), ctxts[j].clone()];
                if gate.get_gate_type() == GateType::Mux {
                    let select: bool = rng.gen();
                    inputs_ptxt.push(PtxtType::Bool(select));
                    inputs_ctxt.push(client_key.encrypt(select));
                }
                let output_value_ptxt = gate.evaluate(&inputs_ptxt);

                let output_value_ctxt = gate.evaluate_encrypted(&server_key, &inputs_ctxt, cycle);
                if gate.get_gate_type() == GateType::Lut {
                    continue;
                }

                assert_eq!(
                    output_value_ptxt,
                    PtxtType::Bool(client_key.decrypt(&output_value_ctxt))
                );

                cycle += 1;
            }
        }
    }
}

#[test]
fn test_evaluate_circuit() {
    let datatype = "bool";
    let (gates_set, mut wire_map, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/2-bit-adder.v",
            false,
            datatype,
        );

    let empty = vec![];
    let mut circuit = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit.sort_circuit();
    assert_eq!(circuit.ordered_gates.len(), 10);
    circuit.compute_levels();

    for input_wire in &input_wires {
        wire_map.insert(input_wire.to_string(), PtxtType::Bool(true));
    }
    wire_map = circuit.evaluate(&wire_map);

    assert_eq!(wire_map.len(), 15);
    assert_eq!(input_wires.len(), 5);

    assert_eq!(wire_map["sum[0]"], PtxtType::Bool(true));
    assert_eq!(wire_map["sum[1]"], PtxtType::Bool(true));
    assert_eq!(wire_map["cout"], PtxtType::Bool(true));
    assert_eq!(wire_map["i0"], PtxtType::Bool(false));
    assert_eq!(wire_map["i1"], PtxtType::Bool(false));
}

#[test]
fn test_evaluate_encrypted_circuit() {
    let datatype = "bool";
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/2-bit-adder.v",
            false,
            datatype,
        );
    let mut ptxt_wire_map = wire_map_im.clone();

    let empty = vec![];
    let mut circuit = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit.sort_circuit();
    circuit.compute_levels();

    // Encrypted
    let (client_key, server_key) = gen_keys();

    // Plaintext
    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), PtxtType::Bool(true));
    }
    ptxt_wire_map = circuit.evaluate(&ptxt_wire_map);

    let mut enc_wire_map = HashMap::new();
    for (wire, value) in wire_map_im {
        match value {
            PtxtType::Bool(val) => {
                enc_wire_map.insert(wire, client_key.encrypt(val));
            }
            _ => unreachable!(),
        }
    }
    for input_wire in &input_wires {
        enc_wire_map.insert(input_wire.to_string(), client_key.encrypt(true));
    }
    let mut circuit = GateCircuit::new(client_key.clone(), server_key, circuit);

    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt(&enc_wire_map[wire_name]),
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], PtxtType::Bool(dec_wire_map[key]));
    }
}

#[test]
fn test_evaluate_encrypted_lut_circuit() {
    let datatype = "bool";
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/8-bit-adder-lut-3-1.v",
            false,
            datatype,
        );
    let input_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/8-bit-adder.inputs.csv",
        datatype,
    );

    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();

    let mut ptxt_wire_map =
        circuit_ptxt.initialize_wire_map(&wire_map_im, &input_wire_map, datatype);

    // Encrypted single bit ctxt
    let (client_key, server_key) = tfhe::shortint::gen_keys(PARAM_MESSAGE_3_CARRY_0);

    // Plaintext
    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
    }
    ptxt_wire_map = circuit_ptxt.evaluate(&ptxt_wire_map);

    let mut circuit = LutCircuit::new(client_key.clone(), server_key, circuit_ptxt);
    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt(&enc_wire_map[wire_name]) == 1,
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], PtxtType::Bool(dec_wire_map[key]));
    }
    debug_println!("wire map: {:?}", dec_wire_map);
}

#[test]
fn test_evaluate_encrypted_high_precision_lut_circuit() {
    let datatype = "bool";
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/8-bit-adder-lut-high-precision.v",
            false,
            datatype,
        );
    let input_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/8-bit-adder.inputs.csv",
        datatype,
    );

    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();
    let mut ptxt_wire_map =
        circuit_ptxt.initialize_wire_map(&wire_map_im, &input_wire_map, datatype);

    // Encrypted
    let (client_key_shortint, server_key_shortint) =
        tfhe::shortint::gen_keys(PARAM_MESSAGE_1_CARRY_1); // single bit ctxt
    let client_key = ClientKeyInt::from(client_key_shortint.clone());
    let server_key = ServerKeyInt::from_shortint(&client_key, server_key_shortint.clone());

    let wopbs_key_shortint = WopbsKeyShortInt::new_wopbs_key(
        &client_key_shortint,
        &server_key_shortint,
        &WOPBS_PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    );
    let wopbs_key = WopbsKeyInt::from(wopbs_key_shortint.clone());

    // Plaintext
    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
    }
    ptxt_wire_map = circuit_ptxt.evaluate(&ptxt_wire_map);

    let mut circuit = HighPrecisionLutCircuit::new(
        wopbs_key_shortint,
        wopbs_key,
        client_key.clone(),
        server_key,
        circuit_ptxt,
    );
    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt_one_block(&enc_wire_map[wire_name]),
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], PtxtType::Bool(dec_wire_map[key] != 0));
    }
    debug_println!("wire map: {:?}", dec_wire_map);
}

#[test]
fn test_evaluate_encrypted_arithmetic_circuit() {
    let datatype = "u16";
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/chi_squared_arith.v",
            true,
            datatype,
        );
    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();

    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            tfhe::shortint::parameters::PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            None,
        )
        .build();
    let (client_key, server_key) = generate_keys(config); // integer ctxt
    let mut circuit = ArithCircuit::new(client_key.clone(), server_key, circuit_ptxt);

    // Input set 1
    let input_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
        datatype,
    );
    let output_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_1.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(value), PtxtType::U8(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U16(value), PtxtType::U16(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U32(value), PtxtType::U32(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U64(value), PtxtType::U64(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            (PtxtType::U128(value), PtxtType::U128(expected_val)) => {
                assert_eq!(value, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }

    // Input set 2
    let input_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_2.inputs.csv",
        datatype,
    );
    let output_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_2.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 2, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(val), PtxtType::U8(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U16(val), PtxtType::U16(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U32(val), PtxtType::U32(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U64(val), PtxtType::U64(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U128(val), PtxtType::U128(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }

    // Input set 3
    let input_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_3.inputs.csv",
        datatype,
    );
    let output_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_3.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 3, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(val), PtxtType::U8(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U16(val), PtxtType::U16(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U32(val), PtxtType::U32(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U64(val), PtxtType::U64(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U128(val), PtxtType::U128(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }

    // Input set 4
    let input_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_4.inputs.csv",
        datatype,
    );
    let output_wire_map = crate::verilog_parser::read_input_wires(
        "hdl-benchmarks/test-cases/chi_squared_arith_4.outputs.csv",
        datatype,
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 4, datatype);

    // Check that the evaluation was correct
    for (wire_name, value) in output_wire_map {
        match (enc_wire_map[&wire_name].decrypt(&client_key), value) {
            (PtxtType::U8(val), PtxtType::U8(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U16(val), PtxtType::U16(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U32(val), PtxtType::U32(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U64(val), PtxtType::U64(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            (PtxtType::U128(val), PtxtType::U128(expected_val)) => {
                assert_eq!(val, expected_val)
            }
            _ => panic!("Decrypted shouldn't be None"),
        };
    }
}
