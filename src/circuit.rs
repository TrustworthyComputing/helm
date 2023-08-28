use crate::gates::{Gate, GateType};
use itertools::Itertools;
use rayon::prelude::*;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    default::Default,
    sync::{Arc, RwLock},
    vec,
};
use termion::color;
use tfhe::{
    boolean::prelude::*,
    integer::{
        wopbs::WopbsKey as WopbsKeyInt, ClientKey as ClientKeyInt, ServerKey as ServerKeyInt,
    },
    prelude::*,
    set_server_key, unset_server_key,
    shortint::{
        ciphertext::Ciphertext, wopbs::WopbsKey as WopbsKeyShortInt,
        ClientKey as ClientKeyShortInt, ServerKey as ServerKeyShortInt,
    },
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

pub trait EvalCircuit<T> {
    type CtxtType;
    type PtxtValType;

    fn encrypt_inputs(
        &mut self,
        wire_map_im: &HashMap<String, Self::PtxtValType>,
        input_wire_map: &HashMap<String, Self::PtxtValType>,
    ) -> HashMap<String, T>;

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, T>,
        current_cycle: usize,
    ) -> HashMap<String, T>;

    fn decrypt_outputs(&self, enc_wire_map: &HashMap<String, T>, verbose: bool);
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

    pub fn initialize_wire_map<T: Default + Clone>(
        &self,
        wire_map_im: &HashMap<String, T>,
        user_inputs: &HashMap<String, T>,
    ) -> HashMap<String, T> {
        let mut wire_map = HashMap::new();
        for (key, value) in wire_map_im.iter() {
            wire_map.insert(key.clone(), value.clone());
        }
        for input_wire in self.input_wires {
            // if no inputs are provided, initialize it to false
            if user_inputs.is_empty() {
                wire_map.insert(input_wire.to_string(), T::default());
            } else if !user_inputs.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not in input wires!", input_wire);
            } else if let Some(user_value) = user_inputs.get(input_wire) {
                wire_map.insert(input_wire.to_string(), user_value.clone());
            } else {
                panic!("\n Input wire \"{}\" not in input wires!", input_wire);
            }
        }
        for wire in self.dff_outputs {
            wire_map.insert(wire.to_string(), T::default());
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

    // TODO: add support for u32 as well
    pub fn evaluate(
        &mut self,
        wire_map: &HashMap<String, bool>,
        cycle: usize,
    ) -> HashMap<String, bool> {
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
                let input_values: Vec<bool> = gate
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
                let output_value = gate.evaluate(&input_values, cycle);

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
            .collect::<HashMap<String, bool>>()
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

impl<'a> EvalCircuit<tfhe::boolean::ciphertext::Ciphertext> for GateCircuit<'a> {
    type CtxtType = tfhe::boolean::ciphertext::Ciphertext;
    type PtxtValType = bool;

    fn encrypt_inputs(
        &mut self,
        wire_map_im: &HashMap<String, bool>,
        input_wire_map: &HashMap<String, bool>,
    ) -> HashMap<String, Self::CtxtType> {
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(value));
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
                enc_wire_map.insert(input_wire.to_string(), self.client_key.encrypt(false));
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not in input wires!", input_wire);
            } else {
                enc_wire_map.insert(
                    input_wire.to_string(),
                    self.client_key.encrypt(input_wire_map[input_wire]),
                );
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(false));
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, Self::CtxtType>,
        cycle: usize,
    ) -> HashMap<String, Self::CtxtType> {
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
                let input_values: Vec<Self::CtxtType> = gate
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

    fn decrypt_outputs(&self, enc_wire_map: &HashMap<String, Self::CtxtType>, verbose: bool) {
        for (i, output_wire) in self.circuit.output_wires.iter().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                println!(
                    " {}: {}",
                    output_wire,
                    self.client_key.decrypt(&enc_wire_map[output_wire])
                );
            }
        }
    }
}

impl<'a> EvalCircuit<Ciphertext> for LutCircuit<'a> {
    type CtxtType = Ciphertext;
    type PtxtValType = bool;

    fn encrypt_inputs(
        &mut self,
        wire_map_im: &HashMap<String, bool>,
        input_wire_map: &HashMap<String, bool>,
    ) -> HashMap<String, Self::CtxtType> {
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(value as u64));
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
                enc_wire_map.insert(input_wire.to_string(), self.client_key.encrypt(0));
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                enc_wire_map.insert(
                    input_wire.to_string(),
                    self.client_key.encrypt(input_wire_map[input_wire] as u64),
                );
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt(0));
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, Self::CtxtType>,
        cycle: usize,
    ) -> HashMap<String, Self::CtxtType> {
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
                let input_values: Vec<Self::CtxtType> = gate
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

    fn decrypt_outputs(&self, enc_wire_map: &HashMap<String, Self::CtxtType>, verbose: bool) {
        for (i, output_wire) in self.circuit.output_wires.iter().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                println!(
                    " {}: {}",
                    output_wire,
                    self.client_key.decrypt(&enc_wire_map[output_wire])
                );
            }
        }
    }
}

impl<'a> EvalCircuit<tfhe::FheUint32> for ArithCircuit<'a> {
    type CtxtType = tfhe::FheUint32;
    type PtxtValType = u32;

    fn encrypt_inputs(
        &mut self,
        wire_map_im: &HashMap<String, u32>,
        input_wire_map: &HashMap<String, u32>,
    ) -> HashMap<String, Self::CtxtType> {
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            if !is_numeric_string(wire) {
                enc_wire_map.insert(
                    wire.to_string(),
                    Self::CtxtType::try_encrypt(value, &self.client_key).unwrap(),
                );
            }
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
                enc_wire_map.insert(
                    input_wire.to_string(),
                    Self::CtxtType::try_encrypt(0, &self.client_key).unwrap(),
                );
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                enc_wire_map.insert(
                    input_wire.to_string(),
                    Self::CtxtType::try_encrypt(input_wire_map[input_wire], &self.client_key)
                        .unwrap(),
                );
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map.insert(
                wire.to_string(),
                Self::CtxtType::try_encrypt(0, &self.client_key).unwrap(),
            );
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, Self::CtxtType>,
        cycle: usize,
    ) -> HashMap<String, Self::CtxtType> {
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
            // set_server_key(self.server_key.clone());
                let mut is_ptxt_op = false;
                // Identify if any of the input wires are constants
                for in_wire in gate.get_input_wires().iter() {
                    if is_numeric_string(in_wire) {
                        is_ptxt_op = true;
                    }
                }
                let output_value = {
                    if is_ptxt_op {
                        let mut ptxt_operand = 0;
                        let mut ctxt_operand: Option<Self::CtxtType> = None;
                        for in_wire in gate.get_input_wires().iter() {
                            if is_numeric_string(in_wire) {
                                ptxt_operand = in_wire.parse::<Self::PtxtValType>().unwrap_or(0);
                            } else {
                                let index = match key_to_index.get(in_wire) {
                                    Some(&index) => index,
                                    None => {
                                        panic!("Input wire {} not in key_to_index map", in_wire)
                                    }
                                };
                                // Read the value of the corresponding key
                                ctxt_operand = Some(eval_values[index].read().unwrap().clone());
                            }
                        }
                        let ct_op = match ctxt_operand {
                            Some(value) => value,
                            None => panic!("Empty ctxt operand!"),
                        };
                        if gate.get_gate_type() == GateType::Add {
                            gate.evaluate_encrypted_add_block_plain(&ct_op, ptxt_operand, cycle)
                        } else if gate.get_gate_type() == GateType::Sub {
                            gate.evaluate_encrypted_sub_block_plain(&ct_op, ptxt_operand, cycle)
                        } else {
                            gate.evaluate_encrypted_mul_block_plain(&ct_op, ptxt_operand, cycle)
                        }
                    } else {
                        let input_values: Vec<Self::CtxtType> = gate
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

    fn decrypt_outputs(&self, enc_wire_map: &HashMap<String, Self::CtxtType>, verbose: bool) {
        for (i, output_wire) in self.circuit.output_wires.iter().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                let decrypted: Self::PtxtValType =
                    enc_wire_map[output_wire].decrypt(&self.client_key);
                println!(" {}: {}", output_wire, decrypted);
            }
        }
    }
}

impl<'a> EvalCircuit<Ciphertext> for HighPrecisionLutCircuit<'a> {
    type CtxtType = Ciphertext;
    type PtxtValType = bool;

    fn encrypt_inputs(
        &mut self,
        wire_map_im: &HashMap<String, bool>,
        input_wire_map: &HashMap<String, bool>,
    ) -> HashMap<String, Self::CtxtType> {
        let mut enc_wire_map = HashMap::<String, _>::new();
        for (wire, &value) in wire_map_im {
            enc_wire_map.insert(
                wire.to_string(),
                self.client_key.encrypt_one_block(value as u64),
            );
        }
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() {
                enc_wire_map.insert(input_wire.to_string(), self.client_key.encrypt_one_block(0));
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                enc_wire_map.insert(
                    input_wire.to_string(),
                    self.client_key
                        .encrypt_one_block(input_wire_map[input_wire] as u64),
                );
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map.insert(wire.to_string(), self.client_key.encrypt_one_block(0));
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, Self::CtxtType>,
        cycle: usize,
    ) -> HashMap<String, Self::CtxtType> {
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
                let input_values: Vec<Self::CtxtType> = gate
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

    fn decrypt_outputs(&self, enc_wire_map: &HashMap<String, Self::CtxtType>, verbose: bool) {
        for (i, output_wire) in self.circuit.output_wires.iter().enumerate() {
            if i > 10 && !verbose {
                println!(
                    "{}[!]{} More than ten output_wires, pass `--verbose` to see output.",
                    color::Fg(color::LightYellow),
                    color::Fg(color::Reset)
                );
                break;
            } else {
                println!(
                    " {}: {}",
                    output_wire,
                    self.client_key
                        .decrypt_one_block(&enc_wire_map[output_wire])
                );
            }
        }
    }
}

#[test]
fn test_gate_evaluation() {
    let (client_key, server_key) = gen_keys();

    let ptxts = vec![true, false];
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
    for mut gate in gates {
        for i in 0..2 {
            for j in 0..2 {
                let mut inputs_ptxt = vec![ptxts[i], ptxts[i]];
                let mut inputs_ctxt = vec![ctxts[i].clone(), ctxts[j].clone()];
                if gate.get_gate_type() == GateType::Mux {
                    let select: bool = rng.gen();
                    inputs_ptxt.push(select);
                    inputs_ctxt.push(client_key.encrypt(select));
                }
                let output_value_ptxt = gate.evaluate(&inputs_ptxt, 1);

                let output_value_enc = gate.evaluate_encrypted(&server_key, &inputs_ctxt, 1);
                if gate.get_gate_type() == GateType::Lut {
                    continue;
                }

                assert_eq!(output_value_ptxt, client_key.decrypt(&output_value_enc));
            }
        }
    }
}

#[test]
fn test_evaluate_circuit() {
    let (gates_set, mut wire_map, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/2-bit-adder.v",
            false,
        );

    let empty = vec![];
    let mut circuit = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit.sort_circuit();
    assert_eq!(circuit.ordered_gates.len(), 10);
    circuit.compute_levels();

    for input_wire in &input_wires {
        wire_map.insert(input_wire.to_string(), true);
    }
    wire_map = circuit.evaluate(&wire_map, 1);

    assert_eq!(wire_map.len(), 15);
    assert_eq!(input_wires.len(), 5);

    assert_eq!(wire_map["sum[0]"], true);
    assert_eq!(wire_map["sum[1]"], true);
    assert_eq!(wire_map["cout"], true);
    assert_eq!(wire_map["i0"], false);
    assert_eq!(wire_map["i1"], false);
}

#[test]
fn test_evaluate_encrypted_circuit() {
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/2-bit-adder.v",
            false,
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
        ptxt_wire_map.insert(input_wire.to_string(), true);
    }
    ptxt_wire_map = circuit.evaluate(&ptxt_wire_map, 1);

    let mut enc_wire_map = HashMap::new();
    for (wire, value) in wire_map_im {
        enc_wire_map.insert(wire, client_key.encrypt(value));
    }
    for input_wire in &input_wires {
        enc_wire_map.insert(input_wire.to_string(), client_key.encrypt(true));
    }
    let mut circuit = GateCircuit::new(client_key.clone(), server_key, circuit);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt(&enc_wire_map[wire_name]),
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], dec_wire_map[key]);
    }
}

#[test]
fn test_evaluate_encrypted_lut_circuit() {
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/8-bit-adder-lut-3-1.v",
            false,
        );
    let input_wire_map =
        crate::verilog_parser::read_input_wires("hdl-benchmarks/test-cases/8-bit-adder.inputs.csv");

    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();

    let mut ptxt_wire_map = circuit_ptxt.initialize_wire_map(&wire_map_im, &input_wire_map);

    // Encrypted single bit ctxt
    let (client_key, server_key) = tfhe::shortint::gen_keys(PARAM_MESSAGE_3_CARRY_0);

    // Plaintext
    for input_wire in &input_wires {
        ptxt_wire_map.insert(input_wire.to_string(), input_wire_map[input_wire]);
    }
    ptxt_wire_map = circuit_ptxt.evaluate(&ptxt_wire_map, 1);

    let mut circuit = LutCircuit::new(client_key.clone(), server_key, circuit_ptxt);
    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt(&enc_wire_map[wire_name]) == 1,
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], dec_wire_map[key]);
    }
    debug_println!("wire map: {:?}", dec_wire_map);
}

#[test]
fn test_evaluate_encrypted_high_precision_lut_circuit() {
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file(
            "hdl-benchmarks/processed-netlists/8-bit-adder-lut-high-precision.v",
            false,
        );
    let input_wire_map =
        crate::verilog_parser::read_input_wires("hdl-benchmarks/test-cases/8-bit-adder.inputs.csv");

    let empty = vec![];
    let mut circuit_ptxt = Circuit::new(gates_set, &input_wires, &empty, &empty);
    circuit_ptxt.sort_circuit();
    circuit_ptxt.compute_levels();
    let mut ptxt_wire_map = circuit_ptxt.initialize_wire_map(&wire_map_im, &input_wire_map);

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
    ptxt_wire_map = circuit_ptxt.evaluate(&ptxt_wire_map, 1);

    let mut circuit = HighPrecisionLutCircuit::new(
        wopbs_key_shortint,
        wopbs_key,
        client_key.clone(),
        server_key,
        circuit_ptxt,
    );
    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);

    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(
            wire_name.to_string(),
            client_key.decrypt_one_block(&enc_wire_map[wire_name]),
        );
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], dec_wire_map[key] != 0);
    }
    debug_println!("wire map: {:?}", dec_wire_map);
}

#[test]
fn test_evaluate_encrypted_arithmetic_circuit() {
    let (gates_set, wire_map_im, input_wires, _, _, _, _) =
        crate::verilog_parser::read_verilog_file::<u32>(
            "hdl-benchmarks/processed-netlists/chi_squared_arith.v",
            true,
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
    let input_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_1.inputs.csv",
    );
    let output_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_1.outputs.csv",
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);

    // Check that the evaluation was correct
    for (wire_name, val) in output_wire_map {
        assert_eq!(val, enc_wire_map[&wire_name].decrypt(&client_key));
    }

    // Input set 2
    let input_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_2.inputs.csv",
    );
    let output_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_2.outputs.csv",
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);

    // Check that the evaluation was correct
    for (wire_name, val) in output_wire_map {
        assert_eq!(val, enc_wire_map[&wire_name].decrypt(&client_key));
    }

    // Input set 3
    let input_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_3.inputs.csv",
    );
    let output_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_3.outputs.csv",
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);

    // Check that the evaluation was correct
    for (wire_name, val) in output_wire_map {
        assert_eq!(val, enc_wire_map[&wire_name].decrypt(&client_key));
    }

    // Input set 4
    let input_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_4.inputs.csv",
    );
    let output_wire_map = crate::verilog_parser::read_input_wires::<u32>(
        "hdl-benchmarks/test-cases/chi_squared_arith_4.outputs.csv",
    );

    let mut enc_wire_map = EvalCircuit::encrypt_inputs(&mut circuit, &wire_map_im, &input_wire_map);
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);

    // Check that the evaluation was correct
    for (wire_name, val) in output_wire_map {
        assert_eq!(val, enc_wire_map[&wire_name].decrypt(&client_key));
    }
}
