use debug_print::debug_println;
use itertools::Itertools;
use rayon::prelude::*;
use std::{
    collections::{HashMap, hash_map::Entry},
    // thread,
    sync::{RwLock, Arc},
    fmt,
    vec,
};
use tfhe::{
    boolean::prelude::*,
    integer::{
        ciphertext::BaseRadixCiphertext,
        IntegerCiphertext,
        ServerKey as ServerKeyInt,
        wopbs as WopbsInt,
        wopbs::WopbsKey as WopbsKeyInt,
    },
    shortint::{
        ciphertext::{KeyswitchBootstrap, CiphertextBase},
        wopbs::WopbsKey as WopbsKeyShortInt,  
    },
};

#[cfg(test)]
use rand::Rng;
#[cfg(test)]
use tfhe::integer::ClientKey as ClientKeyInt;
#[cfg(test)]
use tfhe::shortint::parameters::parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_1_CARRY_1;
#[cfg(test)]
use tfhe::shortint::parameters::PARAM_MESSAGE_1_CARRY_1;

#[derive(Clone, Debug, PartialEq)]
pub enum GateType {
    And,    // and  ID(in0, in1, out);
    Dff,    // dff  ID(in, ouevaluate_encryptedt);
    Lut,    // lut  ID(const, in0, ... , inN-1, out);
    Mux,    // mux  ID(in0, in1, sel, out);
    Nand,   // nand ID(in0, in1, out);
    Nor,    // nor  ID(in0, in1, out);
    Not,    // not  ID(in, out);
    Or,     // or   ID(in0, in1, out);
    Xnor,   // xnor ID(in0, in1, out);
    Xor,    // xor  ID(in0, in1, out);
}

pub trait EvalCircuit<T> {
    fn evaluate(
        &mut self,
        wire_map: &HashMap<String, bool>,
        current_cycle: usize
    ) -> HashMap<String, bool>;
    
    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, T>,
        current_cycle: usize,
    ) -> HashMap<String, T>;
}

pub struct GateCircuit {
    server_key: Option<ServerKey>,
    level_map: HashMap<usize, Vec<Gate>>,
}

impl GateCircuit {
    pub fn new(
        server_key: Option<ServerKey>,
        level_map: HashMap<usize, Vec<Gate>>
    ) -> GateCircuit {
        GateCircuit { server_key, level_map }
    }
}

// Shift the constant by ctxt amount
fn eval_luts(x: u64, lut_entry: u64) -> u64 {
    (lut_entry >> x) & 1
}
  
pub fn generate_lut_radix_helm<F, T>(
    wk: &WopbsKeyShortInt, ct: &T, f: F, lut_entry: &u64
) -> Vec<Vec<u64>>
where
    F: Fn(u64, u64) -> u64,
    T: IntegerCiphertext,
{
    let mut total_bit = 0;
    let block_nb = ct.blocks().len();
    let mut modulus = 1;

    // This contains the basis of each block depending on the degree
    let mut vec_deg_basis = vec![];

    for (i, deg) in ct.moduli().iter().zip(ct.blocks().iter()) {
        modulus *= i;
        let b = f64::log2((deg.degree.0 + 1) as f64).ceil() as u64;
        vec_deg_basis.push(b);
        total_bit += b;
    }

    let mut lut_size = 1 << total_bit;
    if 1 << total_bit < wk.param.polynomial_size.0 as u64 {
        lut_size = wk.param.polynomial_size.0;
    }
    let mut vec_lut = vec![vec![0; lut_size]; ct.blocks().len()];

    let basis = ct.moduli()[0];
    let delta = (1 << 63) /
        (wk.param.message_modulus.0 * wk.param.carry_modulus.0) as u64;

    for lut_index_val in 0..(1 << total_bit) {
        let encoded_with_deg_val = WopbsInt::encode_mix_radix(lut_index_val, &vec_deg_basis, basis);
        let decoded_val = WopbsInt::decode_radix(encoded_with_deg_val.clone(), basis as u64);
        let f_val = f(decoded_val % modulus, *lut_entry) % modulus;
        let encoded_f_val = WopbsInt::encode_radix(f_val, basis, block_nb as u64);
        for lut_number in 0..block_nb {
            vec_lut[lut_number][lut_index_val as usize] = encoded_f_val[lut_number] * delta;
        }
    }
    vec_lut
}
  
pub fn lut(
    wk_si: &WopbsKeyShortInt,
    wk: &WopbsKeyInt,
    sks: &ServerKeyInt,
    lut_const: &usize,
    in_ct: &Vec<CiphertextBase<tfhe::shortint::ciphertext::KeyswitchBootstrap>>
) -> CiphertextBase<tfhe::shortint::ciphertext::KeyswitchBootstrap> {

    // Combine input ctxts into a radix ctxt
    let mut combined_vec = vec![];
    for block in in_ct {
        combined_vec.insert(0, block.clone());
    }
    let radix_ct = 
        BaseRadixCiphertext::<CiphertextBase::<KeyswitchBootstrap>>::from_blocks(combined_vec);

    // KS to WoPBS 
    let radix_ct = wk.keyswitch_to_wopbs_params(&sks, &radix_ct);

    // Generate LUT entries from lut_const
    let lookup_table = generate_lut_radix_helm(&wk_si, &radix_ct, eval_luts, &(*lut_const as u64));

    // Eval PBS
    let radix_ct = wk.wopbs(&radix_ct, &lookup_table);

    // KS to PBS
    let radix_ct = wk.keyswitch_to_pbs_params(&radix_ct);

    // Return LSB
    radix_ct.blocks()[0].clone()
}

impl EvalCircuit<Ciphertext> for GateCircuit {
    fn evaluate(
        &mut self,
        wire_map: &HashMap<String, bool>,
        cycle: usize
    ) -> HashMap<String, bool> {
        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, &value))| ((key, i), Arc::new(RwLock::new(value))))
            .unzip();

        // For each level
        for (_level, gates) in self.level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
            // debug_println!("\n{}) eval_values: {:?}", _level, eval_values);

            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<bool> = gate.input_wires
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not found in key_to_index map", input),
                        };
                        // Read the value of the corresponding key
                        eval_values[index].read().unwrap().clone()
                    })
                    .collect();
                let output_value = gate.evaluate(&input_values, cycle);
                // debug_println!(" {:?} - gate: {:?}", thread::current().id(), gate);

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index].write().unwrap() = output_value;
            });
        };

        key_to_index
            .iter()
            .map(|(&key, &index)| {
                (key.to_string(), eval_values[index].read().unwrap().clone())
            })
            .collect::<HashMap<String, bool>>()
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, Ciphertext>,
        cycle: usize,
    ) -> HashMap<String, Ciphertext> {
        let server_key = self.server_key.as_ref().unwrap();
        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, value))| {
                ((key, i), Arc::new(RwLock::new(value.clone())))
            })
            .unzip();

        // For each level
        let total_levels = self.level_map.len();
        for (level, gates) in self.level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
            // debug_println!("\n{}) eval_values: {:?}", level, eval_values);

            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<Ciphertext> = gate.input_wires
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not found in key_to_index map", input),
                        };

                        // Read the value of the corresponding key
                        eval_values[index].read().unwrap().clone()
                    })
                    .collect();
                let output_value = gate.evaluate_encrypted(&server_key, &input_values, cycle);
                // debug_println!(" {:?} - gate: {:?}", thread::current().id(), gate);

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index].write().unwrap() = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        };

        key_to_index
            .iter()
            .map(|(&key, &index)| {
                (key.to_string(), eval_values[index].read().unwrap().clone())
            })
            .collect()
    }
}

pub struct LutCircuit {
    wopbs_shortkey: WopbsKeyShortInt,
    wopbs_intkey: WopbsKeyInt,
    server_intkey: ServerKeyInt,
    level_map: HashMap<usize, Vec<Gate>>,
}

impl LutCircuit {
    pub fn new(
        wopbs_shortkey: WopbsKeyShortInt,
        wopbs_intkey: WopbsKeyInt,
        server_intkey: ServerKeyInt,
        level_map: HashMap<usize, Vec<Gate>>,
    ) -> LutCircuit {
        LutCircuit { 
            wopbs_shortkey,
            wopbs_intkey,
            server_intkey,
            level_map,
        }
    }
}

impl EvalCircuit<CiphertextBase<KeyswitchBootstrap>> for LutCircuit {
    fn evaluate(
        &mut self,
        wire_map: &HashMap<String, bool>,
        cycle: usize
    ) -> HashMap<String, bool> {

// TODO: replace with LUTs
        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, &value))| ((key, i), Arc::new(RwLock::new(value))))
            .unzip();

        // For each level
        for (_level, gates) in self.level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
            // debug_println!("\n{}) eval_values: {:?}", _level, eval_values);

            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<bool> = gate.input_wires
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not found in key_to_index map", input),
                        };
                        // Read the value of the corresponding key
                        eval_values[index].read().unwrap().clone()
                    })
                    .collect();
                let output_value = gate.evaluate(&input_values, cycle);
                // debug_println!(" {:?} - gate: {:?}", thread::current().id(), gate);

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index].write().unwrap() = output_value;
            });
        };

        key_to_index
            .iter()
            .map(|(&key, &index)| {
                (key.to_string(), eval_values[index].read().unwrap().clone())
            })
            .collect::<HashMap<String, bool>>()
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, CiphertextBase<KeyswitchBootstrap>>,
        cycle: usize,
    ) -> HashMap<String, CiphertextBase<KeyswitchBootstrap>> {

// TODO: replace with LUTs

        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, value))| {
                ((key, i), Arc::new(RwLock::new(value.clone())))
            })
            .unzip();

        // For each level
        let total_levels = self.level_map.len();
        for (level, gates) in self.level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
            // debug_println!("\n{}) eval_values: {:?}", level, eval_values);

            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<CiphertextBase<KeyswitchBootstrap>> = gate.input_wires
                    .iter()
                    .map(|input| {
                        // Get the corresponding index in the wires array
                        let index = match key_to_index.get(input) {
                            Some(&index) => index,
                            None => panic!("Input wire {} not found in key_to_index map", input),
                        };

                        // Read the value of the corresponding key
                        eval_values[index].read().unwrap().clone()
                    })
                    .collect();
                let output_value = gate.evaluate_encrypted_lut(&self.wopbs_shortkey, &self.wopbs_intkey, &self.server_intkey, &input_values, cycle) ;
                // debug_println!(" {:?} - gate: {:?}", thread::current().id(), gate);

                // Get the corresponding index in the wires array
                let output_index = key_to_index[&gate.get_output_wire()];

                // Update the value of the corresponding key
                *eval_values[output_index].write().unwrap() = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        };

        key_to_index
            .iter()
            .map(|(&key, &index)| {
                (key.to_string(), eval_values[index].read().unwrap().clone())
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct Gate {
    _gate_name: String,
    gate_type: GateType,
    input_wires: Vec<String>,
    lut_const: Option<usize>,
    output_wire: String,
    level: usize,
    cycle: usize,
    output: Option<bool>,
    encrypted_output: Option<Ciphertext>,
    encrypted_lut_output: Option<CiphertextBase<KeyswitchBootstrap>>,
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}({:?}) = {:?}({:?}). Level {}", 
            self._gate_name,
            self.output_wire,
            self.output,
            self.gate_type,
            self.input_wires,
            self.level
        )
    }
}

impl Gate {
    pub fn new(
        _gate_name: String, 
        gate_type: GateType,
        input_wires: Vec<String>,
        lut_const: Option<usize>,
        output_wire: String,
        level: usize
    ) -> Self {
        Gate {
            _gate_name,
            gate_type,
            input_wires,
            lut_const,
            output_wire,
            level,
            cycle: 0,
            output: None,
            encrypted_output: None,
            encrypted_lut_output: None,
        }
    }
    
    pub fn get_output_wire(&self) -> String {
        self.output_wire.clone()
    }

    pub fn get_gate_type(&self) -> GateType {
        self.gate_type.clone()
    }

    fn evaluate(&mut self, input_values: &Vec<bool>, cycle: usize) -> bool {
        if let Some(output) = self.output.clone() {
            if self.cycle == cycle {
                return output;
            }
        }
        let output = match self.gate_type {
            GateType::And => input_values.iter().all(|&v| v),
            GateType::Dff => input_values[0],
            GateType::Lut => {
                let mut shift_amt = 0;
                let end = input_values.len() - 1;
                // convert input bits to int:  [1, 1, 0, 1] => 13
                for input_idx in 0..input_values.len() {
                    if input_values[input_idx] {
                        shift_amt += 1 << (end-input_idx);
                    }
                }
                if let Some(lut_const) = self.lut_const {
                    ((lut_const >> shift_amt) & 1) > 0
                } else {
                    panic!("Lut const not provided");
                }
            },
            GateType::Mux => {
                let select_bit = input_values[2];
                (select_bit && input_values[0]) || (!select_bit && input_values[1])
            },
            GateType::Nand => !input_values.iter().all(|&v| v),
            GateType::Nor => !input_values.iter().any(|&v| v),
            GateType::Not => !input_values[0],
            GateType::Or => input_values.iter().any(|&v| v),
            GateType::Xnor => input_values.iter().filter(|&&v| v).count() % 2 != 1,
            GateType::Xor => input_values.iter().filter(|&&v| v).count() % 2 == 1,
        };

        self.output = Some(output);
        self.cycle = cycle;
        output
    }

    fn evaluate_encrypted_lut(
        &mut self,
        wopbs_shortkey: &WopbsKeyShortInt,
        wopbs_intkey: &WopbsKeyInt,
        server_intkey: &ServerKeyInt,
        input_values: &Vec<CiphertextBase<KeyswitchBootstrap>>,
        cycle: usize,
    ) -> CiphertextBase<KeyswitchBootstrap> {
        if let Some(encrypted_lut_output) = self.encrypted_lut_output.clone() {
            if self.cycle == cycle {
                return encrypted_lut_output;
            }
        }
        lut(wopbs_shortkey, wopbs_intkey, server_intkey, &self.lut_const.unwrap(), input_values)
    }
    
    fn evaluate_encrypted(
        &mut self,
        server_key: &ServerKey,
        input_values: &Vec<Ciphertext>,
        cycle: usize,
    ) -> Ciphertext {
        if let Some(encrypted_output) = self.encrypted_output.clone() {
            if self.cycle == cycle {
                return encrypted_output;
            }
        }
        let encrypted_output = match self.gate_type {
            GateType::And => server_key.
                and(&input_values[0], &input_values[1]),
            GateType::Dff => input_values[0].clone(),
            GateType::Lut => { panic!("Can't mix LUTs with Boolean gates!"); },
            GateType::Mux => server_key.mux(&input_values[2],
                &input_values[0], &input_values[1]),
            GateType::Nand => server_key.
                nand(&input_values[0], &input_values[1]),
            GateType::Nor => server_key.
                nor(&input_values[0], &input_values[1]),
            GateType::Not => server_key.not(&input_values[0]),
            GateType::Or => server_key.
                or(&input_values[0], &input_values[1]),
            GateType::Xnor => server_key.
                xnor(&input_values[0], &input_values[1]),
            GateType::Xor => server_key.
                xor(&input_values[0], &input_values[1]),
        };

        self.encrypted_output = Some(encrypted_output.clone());
        encrypted_output
    }
}

// Sort the gates by level so they can be evaluated later in parallel.
pub fn compute_levels(
    gates: &mut Vec<Gate>, inputs: &Vec<String>
) -> HashMap::<usize, Vec<Gate>> {
    // Initialization of inputs to true
    let mut wire_levels = HashMap::new();
    for input in inputs {
        wire_levels.insert(input.to_string(), 0);
    }
    
    let mut level_map = HashMap::new();
    for mut gate in gates {
        if gate.gate_type == GateType::Dff {
            match level_map.entry(std::usize::MAX) {
                Entry::Vacant(e) => { e.insert(vec![(*gate).clone()]); },
                Entry::Occupied(mut e) => { e.get_mut().push((*gate).clone()); }
            }
            gate.level = std::usize::MAX;
            continue;
        }
        // Find the max depth of the input wires
        let mut depth = 0;
        gate.input_wires.iter().for_each(|input| {
            let input_depth = match wire_levels.get(input) {
                Some(value) => *value,
                None => panic!("Input {} not found in wire_map", input),
            };
            depth = std::cmp::max(depth, input_depth + 1);
        });

        match level_map.entry(depth) {
            Entry::Vacant(e) => { e.insert(vec![(*gate).clone()]); },
            Entry::Occupied(mut e) => { e.get_mut().push((*gate).clone()); }
        }
        gate.level = depth;
        wire_levels.insert(gate.get_output_wire(), depth);
    }

    level_map
}

// Evaluate each gate in topological order
pub fn _evaluate_circuit_sequentially(
    gates: &mut Vec<Gate>,
    wire_map: &mut HashMap<String, bool>,
    cycle: usize,
) {
    for gate in gates {
        debug_println!("evaluating gate: {:?}", gate);

        let input_values = gate.input_wires
            .iter()
            .map(|input| {
                match wire_map.get(input) {
                    Some(input_value) => *input_value,
                    None => panic!("Input {} not found in wire_map", input),
                }
            })
            .collect();

        let output_value = gate.evaluate(&input_values, cycle);
        wire_map.insert(gate.get_output_wire(), output_value);
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
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Or, 
            vec![],
            None, 
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Nor, 
            vec![],
            None,
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Xor, 
            vec![], 
            None,
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Nand, 
            vec![], 
            None,
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Not, 
            vec![],
            None,
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Xnor, 
            vec![], 
            None,
            String::from(""), 
            0
        ),
        Gate::new(
            String::from(""), 
            GateType::Mux, 
            vec![], 
            None,
            String::from(""), 
            0
        ),
    ];
    let mut rng = rand::thread_rng();
    for mut gate in gates {
        for i in 0..2 {
            for j in 0..2 {
                let mut inputs_ptxt = vec![ptxts[i], ptxts[i]];
                let mut inputs_ctxt = vec![ctxts[i].clone(), ctxts[j].clone()];
                if gate.gate_type == GateType::Mux {
                    let select: bool = rng.gen();
                    inputs_ptxt.push(select);
                    inputs_ctxt.push(client_key.encrypt(select));
                }
                let output_value_ptxt = gate.evaluate(&inputs_ptxt, 1);

                let output_value_enc = gate.evaluate_encrypted(
                    &server_key, &inputs_ctxt, 1
                );
                if gate.gate_type == GateType::Lut {
                    continue;
                }

                assert_eq!(output_value_ptxt, client_key.decrypt(&output_value_enc));
            }
        }
    }

}

#[test]
fn test_evaluate_circuit_parallel() {
    let (mut gates, mut wire_map, inputs, _, _,_) = 
        crate::verilog_parser::read_verilog_file("verilog-files/netlists/2bit_adder.v");

    let level_map = compute_levels(&mut gates, &inputs);
    for input_wire in &inputs {
        wire_map.insert(input_wire.to_string(), true);
    }

    let mut circuit = GateCircuit::new(None, level_map);
    wire_map = EvalCircuit::evaluate(&mut circuit, &wire_map, 1);

    assert_eq!(gates.len(), 10);
    assert_eq!(wire_map.len(), 15);
    assert_eq!(inputs.len(), 5);

    assert_eq!(wire_map["sum[0]"], true);
    assert_eq!(wire_map["sum[1]"], true);
    assert_eq!(wire_map["cout"], true);
    assert_eq!(wire_map["i0"], false);
    assert_eq!(wire_map["i1"], false);
}

#[test]
fn test_evaluate_encrypted_circuit_parallel() {
    let (mut gates, wire_map_im, inputs, _, _,_) = 
        crate::verilog_parser::read_verilog_file("verilog-files/netlists/2bit_adder.v");
    let mut ptxt_wire_map = wire_map_im.clone();

    // Encrypted
    let (client_key, server_key) = gen_keys();
    let level_map = compute_levels(&mut gates, &inputs);
    
    // Plaintext
    for input_wire in &inputs {
        ptxt_wire_map.insert(input_wire.to_string(), true);
    }
    let mut circuit = GateCircuit::new(Some(server_key), level_map);
    ptxt_wire_map = EvalCircuit::evaluate(&mut circuit, &ptxt_wire_map, 1);

    let mut enc_wire_map = HashMap::new();
    for (wire, value) in wire_map_im {
        enc_wire_map.insert(wire, client_key.encrypt(value));
    }
    for input_wire in &inputs {
        enc_wire_map.insert(input_wire.to_string(), client_key.encrypt(true));
    }
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
    
    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(wire_name.to_string(), client_key.decrypt(&enc_wire_map[wire_name]));
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], dec_wire_map[key]);
    }
}

#[test]
fn test_evaluate_encrypted_lut_circuit_parallel() {
    let (mut gates, wire_map_im, inputs, _, _,_) = 
        crate::verilog_parser::read_verilog_file("verilog-files/netlists/8bit-adder-lut.out.v");
    let mut ptxt_wire_map = wire_map_im.clone();

    // Encrypted
    let (cks_shortint, sks_shortint) = tfhe::shortint::gen_keys(PARAM_MESSAGE_1_CARRY_1); // single bit ctxt
    let cks = ClientKeyInt::from(cks_shortint.clone());
    let sks = ServerKeyInt::from_shortint(&cks, sks_shortint.clone());

    let wopbs_key_shortint = WopbsKeyShortInt::new_wopbs_key(&cks_shortint, &sks_shortint, &WOPBS_PARAM_MESSAGE_1_CARRY_1);
    let wopbs_key = WopbsKeyInt::from(wopbs_key_shortint.clone());

    let level_map = compute_levels(&mut gates, &inputs);
    
    // Plaintext
    for input_wire in &inputs {
        ptxt_wire_map.insert(input_wire.to_string(), true);
    }
    let mut circuit = LutCircuit::new(wopbs_key_shortint, wopbs_key, sks, level_map);
    ptxt_wire_map = EvalCircuit::evaluate(&mut circuit, &ptxt_wire_map, 1);

    let mut enc_wire_map = HashMap::new();
    for (wire, value) in wire_map_im {
        enc_wire_map.insert(wire, cks.encrypt_one_block(value as u64));
    }
    for input_wire in &inputs {
        enc_wire_map.insert(input_wire.to_string(), cks.encrypt_one_block(1));
    }
    enc_wire_map = EvalCircuit::evaluate_encrypted(&mut circuit, &enc_wire_map, 1);
    
    let mut dec_wire_map = HashMap::new();
    for wire_name in enc_wire_map.keys().sorted() {
        dec_wire_map.insert(wire_name.to_string(), cks.decrypt_one_block(&enc_wire_map[wire_name]));
    }

    // Check that encrypted and plaintext evaluations are equal
    for key in ptxt_wire_map.keys() {
        assert_eq!(ptxt_wire_map[key], dec_wire_map[key] != 0);
    }
    debug_println!("wire map: {:?}", dec_wire_map);
}
