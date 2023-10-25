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
use concrete_core::prelude::*;
use concrete_core::specification::parameters::{LweDimension, PolynomialSize, GlweDimension};


use crate::{FheType, PtxtType};

/// The plaintext associated with true: 1/8 (for concrete-core Boolean)
static PLAINTEXT_TRUE: u32 = 1 << (32 - 3);

/// The plaintext associated with false: -1/8 (for concrete-core Boolean)
static PLAINTEXT_FALSE: u32 = 7 << (32 - 3);

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
        &mut self,
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

pub struct CircuitCuda<'a> {
    circuit: Circuit<'a>,
    default_engine: DefaultEngine,
    cuda_engine: CudaEngine,
    host_client_key: LweSecretKey32,
    device_bootstrap_key: CudaFourierLweBootstrapKey32,
    device_keyswitch_key: CudaLweKeyswitchKey32,
    lwe_dim_orig: LweDimension,
    noise: Variance,
}

pub struct LutCircuitCuda<'a> {
    circuit: Circuit<'a>,
    default_engine: DefaultEngine,
    cuda_engine: CudaEngine,
    cuda_amortized_engine: AmortizedCudaEngine,
    host_client_key: LweSecretKey64,
    host_client_key_intermediate: LweSecretKey64,
    device_bootstrap_key: CudaFourierLweBootstrapKey64,
    device_keyswitch_key: CudaLweKeyswitchKey64,
    lwe_dim_orig: LweDimension,
    glwe_dim: GlweDimension,
    noise: Variance,
    poly_degree: PolynomialSize,
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

        let eval_values = wire_map
            .iter()
            .map(|(key, &value)| (key.clone(), Arc::new(RwLock::new(value))))
            .collect::<HashMap<_, _>>();

        // For each level
        for (_level, gates) in self.level_map.iter_mut().sorted_by_key(|(level, _)| *level) {
            // Evaluate all the gates in the level in parallel
            gates.par_iter_mut().for_each(|gate| {
                let input_values: Vec<PtxtType> = gate
                    .get_input_wires()
                    .iter()
                    .map(|input| *eval_values[input].read().unwrap())
                    .collect();

                // Update the value of the corresponding key
                *eval_values[&gate.get_output_wire()]
                    .write()
                    .expect("Failed to acquire write lock") = gate.evaluate(&input_values);
            });
        }

        // Convert eval_values to the expected return type
        eval_values
            .iter()
            .map(|(key, value)| (key.to_string(), *value.read().unwrap()))
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

impl<'a> CircuitCuda<'a> {
    pub fn new(
        circuit: Circuit,
        default_engine: DefaultEngine,
        cuda_engine: CudaEngine,
        host_client_key: LweSecretKey32,
        device_bootstrap_key: CudaFourierLweBootstrapKey32,
        device_keyswitch_key: CudaLweKeyswitchKey32,
        lwe_dim_orig: LweDimension,
        noise: Variance,
    ) -> CircuitCuda {
        CircuitCuda {
            circuit,
            default_engine,
            cuda_engine,
            host_client_key,
            device_bootstrap_key,
            device_keyswitch_key,
            lwe_dim_orig,
            noise,
        }
    }
}

impl<'a> LutCircuitCuda<'a> {
    pub fn new(
        circuit: Circuit,
        default_engine: DefaultEngine,
        cuda_engine: CudaEngine,
        cuda_amortized_engine: AmortizedCudaEngine,
        host_client_key: LweSecretKey64,
        host_client_key_intermediate: LweSecretKey64,
        device_bootstrap_key: CudaFourierLweBootstrapKey64,
        device_keyswitch_key: CudaLweKeyswitchKey64,
        lwe_dim_orig: LweDimension,
        glwe_dim: GlweDimension,
        noise: Variance,
        poly_degree: PolynomialSize,
    ) -> LutCircuitCuda {
        LutCircuitCuda {
            circuit,
            default_engine,
            cuda_engine,
            cuda_amortized_engine,
            host_client_key,
            host_client_key_intermediate,
            device_bootstrap_key,
            device_keyswitch_key,
            lwe_dim_orig,
            glwe_dim,
            noise,
            poly_degree,
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

        let eval_values = enc_wire_map
            .iter()
            .map(|(key, value)| (key.clone(), Arc::new(RwLock::new(value.clone()))))
            .collect::<HashMap<_, _>>();

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
                    .map(|input| eval_values[input].read().unwrap().clone())
                    .collect();

                // Update the value of the corresponding key
                *eval_values[&gate.get_output_wire()].write().unwrap() =
                    gate.evaluate_encrypted(&self.server_key, &input_values, cycle);
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        eval_values
            .iter()
            .map(|(key, value)| (key.to_string(), value.read().unwrap().clone()))
            .collect::<HashMap<_, _>>()
    }

    fn decrypt_outputs(
        &mut self,
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

impl<'a> EvalCircuit<LweCiphertext64> for LutCircuitCuda<'a> {
    fn encrypt_inputs(
        &mut self,
        wire_set: &HashSet<String>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, LweCiphertext64> {
        let zero_ptxt: Plaintext64 = self.default_engine.create_plaintext_from(&0).unwrap();

        let mut enc_wire_map = wire_set
            .iter()
            .map(|wire| (wire.to_string(), self.default_engine.trivially_encrypt_lwe_ciphertext(self.lwe_dim_orig.to_lwe_size(), &zero_ptxt).unwrap()))
            .collect::<HashMap<_, _>>();
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() || input_wire_map.contains_key("dummy") {
                enc_wire_map.insert(input_wire.to_string(), self.default_engine.encrypt_lwe_ciphertext(&self.host_client_key, &zero_ptxt, self.noise).unwrap());
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                match input_wire_map[input_wire] {        
                    PtxtType::Bool(v) => {
                        let shifted_input = (v as u64) << 60;
                        let input_pt: Plaintext64 = self.default_engine.create_plaintext_from(&shifted_input).unwrap();
                        enc_wire_map
                            .insert(input_wire.to_string(), self.default_engine.encrypt_lwe_ciphertext(&self.host_client_key, &input_pt, self.noise).unwrap());
                    }
                    _ => unreachable!(),
                }
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map
                .insert(wire.to_string(), self.default_engine.encrypt_lwe_ciphertext(&self.host_client_key, &zero_ptxt, self.noise).unwrap());
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, LweCiphertext64>,
        _cycle: usize,
        _ptxt_type: &str,
    ) -> HashMap<String, LweCiphertext64> {
        // Make sure the sort circuit function has run.
        assert!(self.circuit.gates.is_empty());
        // Make sure the compute_levels function has run.
        assert!(self.circuit.ordered_gates.is_empty());

        let (key_to_index, eval_values): (HashMap<_, _>, Vec<_>) = enc_wire_map
            .iter()
            .enumerate()
            .map(|(i, (key, value))| ((key, i), Arc::new(RwLock::new(value.clone()))))
            .unzip();

        let h_bridge_cleartext: Cleartext64 = self.default_engine.create_cleartext_from(&2).unwrap();

        // For each level
        let total_levels = self.circuit.level_map.len();
        for (level, gates) in self
            .circuit
            .level_map
            .iter_mut()
            .sorted_by_key(|(level, _)| *level)
        {
            let mut input_vec: LweCiphertextVector64 = self.default_engine
            .zero_encrypt_lwe_ciphertext_vector(&self.host_client_key, self.noise, LweCiphertextCount(gates.len()))
            .unwrap();
            let num_gates = gates.len();

            // bridge the ctxts and store in input_vec
            let mut array_idx = 0;
            for gate in gates.iter() {
                let input_values: Vec<LweCiphertext64> = gate
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
                if gate.get_input_wires().len() == 2 {
                    let mut tmp_ct = input_values[1].clone();
                    self.default_engine.fuse_mul_lwe_ciphertext_cleartext(&mut tmp_ct, &h_bridge_cleartext).unwrap();
                    self.default_engine
                    .fuse_add_lwe_ciphertext(&mut tmp_ct, &input_values[0])
                    .unwrap();
                    let err_chk = self.default_engine.discard_store_lwe_ciphertext(
                        &mut input_vec,
                        &tmp_ct,
                        LweCiphertextIndex(array_idx as usize),
                    );
                    match err_chk {
                        Ok(_value) => {}
                        Err(error) => {
                            println!("Error @ index={:?}: {}", &array_idx, error);
                        }
                    }
                } else if gate.get_input_wires().len() == 1 {
                    let err_chk = self.default_engine.discard_store_lwe_ciphertext(
                        &mut input_vec,
                        &input_values[0],
                        LweCiphertextIndex(array_idx as usize),
                    );
                    match err_chk {
                        Ok(_value) => {}
                        Err(error) => {
                            println!("Error @ index={:?}: {}", &array_idx, error);
                        }
                    }
                } else {
                    panic!("Only 2:1 and 1:1 LUTs are supported on the GPU!");
                }
                array_idx += 1;
            }

            // Upload input_vec to GPU
            let mut d_input_vec: CudaLweCiphertextVector64 = self.cuda_engine
            .convert_lwe_ciphertext_vector(&input_vec)
            .unwrap();    

            // Build LUT constants
            let mut lut = vec![0u64; self.poly_degree.0 * num_gates];
            
            for j in 0..num_gates {
                for i in 0..self.poly_degree.0 {
                    if i < 16 { // map 0 to lut_const[0]
                        let l = ((64 * gates[j].get_lut_const().as_ref().unwrap()[0]) as f64 * 2_f64.powi((54) as i32)) as u64;
                        lut[j * self.poly_degree.0 + i] = l;
                    } else if i < 80 { // map 1 to lut_const[1]
                        let l = ((64 * gates[j].get_lut_const().as_ref().unwrap()[1]) as f64 * 2_f64.powi((54) as i32)) as u64;
                        lut[j * self.poly_degree.0 + i] = l;
                    } else if i < 144 { // map 2 to lut_const[2]
                        let l = ((64 * gates[j].get_lut_const().as_ref().unwrap()[2]) as f64 * 2_f64.powi((54) as i32)) as u64;
                        lut[j * self.poly_degree.0 + i] = l;
                    } else if i < 208 { // map 3 to lut_const[3]
                        let l = ((64 * gates[j].get_lut_const().as_ref().unwrap()[3]) as f64 * 2_f64.powi((54) as i32)) as u64;
                        lut[j * self.poly_degree.0 + i] = l;
                    } else { // map 0 to lut_const[0]; offset needed for some reason
                        let offset = if gates[j].get_lut_const().as_ref().unwrap()[0] > 0 { 896 } else { 0 };
                        let l = ((gates[j].get_lut_const().as_ref().unwrap()[0]*64+offset) as f64 * 2_f64.powi((54) as i32)) as u64;
                        lut[j * self.poly_degree.0 + i] = l;
                    }
                }

                // let mut small_lut = vec![0u64; 32];

                // // Encode entries with redundancy
                // let mut idx = 31;
                // for i in 0..gates[j].get_lut_const().as_ref().unwrap().len() {
                //     small_lut[idx] = gates[j].get_lut_const().as_ref().unwrap()[i];
                //     idx = (idx + 1) % 32;
                //     small_lut[idx] = gates[j].get_lut_const().as_ref().unwrap()[i];
                //     idx = (idx + 1) % 32;
                // }

                // println!("lut const: {:?}", gates[j].get_lut_const().as_ref().unwrap());
                // println!("small_lut: {:?}", &small_lut);

                // for i in 0..self.poly_degree.0 {
                //     let l = small_lut[i >> 4] << 59;
                //     lut[j * self.poly_degree.0 + i] = l;
                // }
            }
            
            // Encode LUT constants as a GLWE ctxt vector
            let host_lut_plaintext_vector = self.default_engine.create_plaintext_vector_from(&lut).unwrap();
            let host_lut = self.default_engine
            .trivially_encrypt_glwe_ciphertext_vector(
                self.glwe_dim.to_glwe_size(),
                GlweCiphertextCount(gates.len()),
                &host_lut_plaintext_vector,
            )
            .unwrap();
    
            // Upload GLWE ctxt vector to GPU
            let d_lut: CudaGlweCiphertextVector64 =
            self.cuda_engine.convert_glwe_ciphertext_vector(&host_lut).unwrap();

            // Allocate output ciphertext array for bootstrapping
            let h_zero_output_ciphertext_vector: LweCiphertextVector64 = self.default_engine
            .zero_encrypt_lwe_ciphertext_vector(&self.host_client_key_intermediate, self.noise, LweCiphertextCount(gates.len()))
            .unwrap();
            
            // Upload output ciphertext array to GPU
            let mut d_output_ciphertext_vector: CudaLweCiphertextVector64 = self.cuda_engine
                .convert_lwe_ciphertext_vector(&h_zero_output_ciphertext_vector)
                .unwrap();
    
            // Compute all LUTs in the level on the GPU
            self.cuda_amortized_engine
            .discard_bootstrap_lwe_ciphertext_vector(
                &mut d_output_ciphertext_vector,
                &d_input_vec,
                &d_lut,
                &self.device_bootstrap_key,
            )
            .unwrap();
    
            // Keyswitch all output ciphertexts on the GPU
            self.cuda_engine
            .discard_keyswitch_lwe_ciphertext_vector(
                &mut d_input_vec,
                &d_output_ciphertext_vector,
                &self.device_keyswitch_key,
            )
            .unwrap();
    
            // Transfer output ctxts back to host
            input_vec = self.cuda_engine
            .convert_lwe_ciphertext_vector(&d_input_vec)
            .unwrap();

            // Create ptxt of 0
            let zero_ptxt: Plaintext64 = self.default_engine.create_plaintext_from(&0).unwrap();
            // Write the output wires of each LUT 
            for i in 0..gates.len() {
                let mut ct_extract: LweCiphertext64;
                ct_extract = self.default_engine.trivially_encrypt_lwe_ciphertext(self.lwe_dim_orig.to_lwe_size(), &zero_ptxt).unwrap();
                let output_index = key_to_index[&gates[i].get_output_wire()];
                let err_chk = self.default_engine.discard_load_lwe_ciphertext(&mut ct_extract, &input_vec, LweCiphertextIndex(i));
                match err_chk {
                    Ok(_value) => {}
                    Err(error) => {
                        println!("Error: {}", error);
                    }
                }
                *eval_values[output_index]
                    .write()
                    .expect("Failed to acquire write lock") = ct_extract;
            }
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }
        key_to_index
            .iter()
            .map(|(&key, &index)| (key.to_string(), eval_values[index].read().unwrap().clone()))
            .collect()
    }

    fn decrypt_outputs(
        &mut self,
        enc_wire_map: &HashMap<String, LweCiphertext64>,
        verbose: bool,
    ) -> HashMap<String, PtxtType> {
        let mut decrypted_outputs = HashMap::new();
        for output_wire in self.circuit.output_wires {
            let pt_extract = self.default_engine.decrypt_lwe_ciphertext(&self.host_client_key, &enc_wire_map[output_wire]).unwrap();
            let raw_pt_extract = self.default_engine.retrieve_plaintext(&pt_extract).unwrap();
            let output = raw_pt_extract >> 59;
            let carry = output % 2;
            let output = ((output >> 1) + carry) % (1 << 4);
            decrypted_outputs.insert(output_wire.clone(), PtxtType::U64(output));
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

impl<'a> EvalCircuit<LweCiphertext32> for CircuitCuda<'a> {
    fn encrypt_inputs(
        &mut self,
        wire_set: &HashSet<String>,
        input_wire_map: &HashMap<String, PtxtType>,
    ) -> HashMap<String, LweCiphertext32> {
        let zero_ptxt: Plaintext32 = self.default_engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap();
        let mut enc_wire_map = wire_set
            .iter()
            .map(|wire| (wire.to_string(), self.default_engine.trivially_encrypt_lwe_ciphertext(self.lwe_dim_orig.to_lwe_size(), &zero_ptxt).unwrap()))
            .collect::<HashMap<_, _>>();
        for input_wire in self.circuit.input_wires {
            // if no inputs are provided, initialize it to false
            if input_wire_map.is_empty() || input_wire_map.contains_key("dummy") {
                enc_wire_map.insert(input_wire.to_string(), self.default_engine.encrypt_lwe_ciphertext(&self.host_client_key, &zero_ptxt, self.noise).unwrap());
            } else if !input_wire_map.contains_key(input_wire) {
                panic!("\n Input wire \"{}\" not found in input wires!", input_wire);
            } else {
                match input_wire_map[input_wire] {        
                    PtxtType::Bool(v) => {
                        let shifted_input = if v {PLAINTEXT_TRUE} else {PLAINTEXT_FALSE};
                        let input_pt: Plaintext32 = self.default_engine.create_plaintext_from(&shifted_input).unwrap();
                        enc_wire_map
                            .insert(input_wire.to_string(), self.default_engine.encrypt_lwe_ciphertext(&self.host_client_key, &input_pt, self.noise).unwrap());
                    }
                    _ => unreachable!(),
                }
            }
        }
        for wire in self.circuit.dff_outputs {
            enc_wire_map
                .insert(wire.to_string(), self.default_engine.encrypt_lwe_ciphertext(&self.host_client_key, &zero_ptxt, self.noise).unwrap());
        }

        enc_wire_map
    }

    fn evaluate_encrypted(
        &mut self,
        enc_wire_map: &HashMap<String, LweCiphertext32>,
        _cycle: usize,
        _ptxt_type: &str,
    ) -> HashMap<String, LweCiphertext32> {
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
            // Create HashMaps to store gate counts and storage indices for each gate type
            let mut gate_counts: HashMap<GateType, usize> = HashMap::new();
            let mut gate_idx_by_type: HashMap<GateType, usize> = HashMap::new();
            // Iterate through the gates and count each gate type
            for gate in gates.clone() {
                let counter = gate_counts.entry(gate.get_gate_type()).or_insert(0);
                *counter += 1;
                gate_idx_by_type.entry(gate.get_gate_type()).or_insert(0);
            }
            
            // Create a HashMap to store ciphertext vectors for inputs to GPU gates
            let mut gate_vec_map: HashMap<GateType, Vec<LweCiphertextVector32>> = HashMap::new();
            for (gate_type, gate_count) in gate_counts.clone() {
                let mut gate_vec: Vec<LweCiphertextVector32> = vec![];
                let tmp_vec: LweCiphertextVector32 = self.default_engine
                .zero_encrypt_lwe_ciphertext_vector(&self.host_client_key, self.noise, LweCiphertextCount(gate_count))
                .unwrap();
                gate_vec.push(tmp_vec);
                if gate_type != GateType::Not { // Need two input vectors for all gates except NOT (no MUX support either)
                    let tmp_vec_2: LweCiphertextVector32 = self.default_engine
                    .zero_encrypt_lwe_ciphertext_vector(&self.host_client_key, self.noise, LweCiphertextCount(gate_count))
                    .unwrap();
                    gate_vec.push(tmp_vec_2);
                }
                gate_vec_map.insert(gate_type, gate_vec);
            }

            // Store ctxts in corresponding ctxt vectors
            for gate in gates.iter() {
                let input_values: Vec<LweCiphertext32> = gate
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

                // Stores input wires in corresponding vector
                let array_idx = gate_idx_by_type.get(&gate.get_gate_type()).unwrap();
                for i in 0..input_values.len() {
                    gate_vec_map.entry(gate.get_gate_type()).and_modify(|ct_vecs| {
                        self.default_engine.discard_store_lwe_ciphertext(
                            &mut ct_vecs[i],
                            &input_values[i],
                            LweCiphertextIndex(*array_idx),
                        ).unwrap();
                    });
                }
                // Update gate counter for next gate
                gate_idx_by_type.entry(gate.get_gate_type()).and_modify(|ctr| {*ctr += 1});
            }

            // Upload input vecs to GPU
            let mut d_input_vecs: HashMap<GateType, CudaLweCiphertextVector32> = HashMap::new();
            let mut d_input_vecs_2: HashMap<GateType, CudaLweCiphertextVector32> = HashMap::new();
            for (gate_type, h_input_vecs) in gate_vec_map {
                let tmp_d_vec = self.cuda_engine.convert_lwe_ciphertext_vector(&h_input_vecs[0]).unwrap();
                d_input_vecs.insert(gate_type.clone(), tmp_d_vec);
                if gate_type != GateType::Not {
                    let tmp_d_vec_2 = self.cuda_engine.convert_lwe_ciphertext_vector(&h_input_vecs[1]).unwrap();
                    d_input_vecs_2.insert(gate_type, tmp_d_vec_2);    
                }
            }
                
            // Allocate output ciphertext arrays for bootstrapping
            let mut h_output_ctxt_vecs: HashMap<GateType, LweCiphertextVector32> = HashMap::new();
            for (gate_type, gate_count) in gate_counts.clone() {
                let tmp_h_vec = self.default_engine.zero_encrypt_lwe_ciphertext_vector(&self.host_client_key, self.noise, LweCiphertextCount(gate_count)).unwrap();
                h_output_ctxt_vecs.insert(gate_type, tmp_h_vec);
            }
            
            // Upload output ciphertext arrays to GPU
            let mut d_output_ctxt_vecs: HashMap<GateType, CudaLweCiphertextVector32> = HashMap::new();
            for (gate_type, out_vec) in &h_output_ctxt_vecs {
                let tmp_d_vec = self.cuda_engine.convert_lwe_ciphertext_vector(out_vec).unwrap();
                d_output_ctxt_vecs.insert(gate_type.clone(), tmp_d_vec);
            }

            // Compute all gate types in the level on the GPU
            for (gate_type, _) in gate_counts {
                let d_ct_vec_1 = d_input_vecs.get(&gate_type).unwrap();
                if gate_type == GateType::Not {
                    d_output_ctxt_vecs.entry(gate_type).and_modify(|ct_vec| {
                        self.cuda_engine.discard_not_lwe_ciphertext_vector(
                                ct_vec,
                                &d_ct_vec_1,
                        ).unwrap();
                    });
                } else {
                    let d_ct_vec_2 = d_input_vecs_2.get(&gate_type).unwrap();
                    if gate_type == GateType::And {
                        d_output_ctxt_vecs.entry(gate_type).and_modify(|ct_vec| {
                            self.cuda_engine.discard_and_lwe_ciphertext_vector(
                                ct_vec,
                                &d_ct_vec_1,
                                &d_ct_vec_2,
                                &self.device_bootstrap_key,
                                &self.device_keyswitch_key,
                            ).unwrap();
                        });    
                    } else if gate_type == GateType::Nand {
                        d_output_ctxt_vecs.entry(gate_type).and_modify(|ct_vec| {
                            self.cuda_engine.discard_nand_lwe_ciphertext_vector(
                                ct_vec,
                                &d_ct_vec_1,
                                &d_ct_vec_2,
                                &self.device_bootstrap_key,
                                &self.device_keyswitch_key,
                            ).unwrap();
                        });    
                    } else if gate_type == GateType::Or {
                        d_output_ctxt_vecs.entry(gate_type).and_modify(|ct_vec| {
                            self.cuda_engine.discard_or_lwe_ciphertext_vector(
                                ct_vec,
                                &d_ct_vec_1,
                                &d_ct_vec_2,
                                &self.device_bootstrap_key,
                                &self.device_keyswitch_key,
                            ).unwrap();
                        });   
                    } else if gate_type == GateType::Nor {
                        d_output_ctxt_vecs.entry(gate_type).and_modify(|ct_vec| {
                            self.cuda_engine.discard_nor_lwe_ciphertext_vector(
                                ct_vec,
                                &d_ct_vec_1,
                                &d_ct_vec_2,
                                &self.device_bootstrap_key,
                                &self.device_keyswitch_key,
                            ).unwrap();
                        });   
                    } else if gate_type == GateType::Xor {
                        d_output_ctxt_vecs.entry(gate_type).and_modify(|ct_vec| {
                            self.cuda_engine.discard_xor_lwe_ciphertext_vector(
                                ct_vec,
                                &d_ct_vec_1,
                                &d_ct_vec_2,
                                &self.device_bootstrap_key,
                                &self.device_keyswitch_key,
                            ).unwrap();
                        });   
                    } else if gate_type == GateType::Xnor {
                        d_output_ctxt_vecs.entry(gate_type).and_modify(|ct_vec| {
                            self.cuda_engine.discard_xnor_lwe_ciphertext_vector(
                                ct_vec,
                                &d_ct_vec_1,
                                &d_ct_vec_2,
                                &self.device_bootstrap_key,
                                &self.device_keyswitch_key,
                            ).unwrap();
                        });   
                    }
                }
            }
        
            // Keep track of current index for each output vector 
            let mut vec_idx_by_gate_type: HashMap<GateType, usize> = HashMap::new();

            // Transfer output ctxt vectors back to host
            for (gate_type, out_vec) in d_output_ctxt_vecs {
                h_output_ctxt_vecs.entry(gate_type.clone()).and_modify(|h_ct_vec| {
                    *h_ct_vec = self.cuda_engine.convert_lwe_ciphertext_vector(&out_vec).unwrap();
                });
                vec_idx_by_gate_type.insert(gate_type, 0);
            }

            // Create ptxt of 0
            let zero_ptxt: Plaintext32 = self.default_engine.create_plaintext_from(&PLAINTEXT_FALSE).unwrap();
            
            // Write the output wires of each LUT 
            for i in 0..gates.len() {
                let curr_gate_type : &GateType = &gates[i].get_gate_type();
                let mut ct_extract: LweCiphertext32;
                ct_extract = self.default_engine.trivially_encrypt_lwe_ciphertext(self.lwe_dim_orig.to_lwe_size(), &zero_ptxt).unwrap();
                let output_index = key_to_index[&gates[i].get_output_wire()];
                let err_chk = self.default_engine.discard_load_lwe_ciphertext(&mut ct_extract, &h_output_ctxt_vecs.get(curr_gate_type).unwrap(), LweCiphertextIndex(*vec_idx_by_gate_type.get(curr_gate_type).unwrap()));
                match err_chk {
                    Ok(_value) => {}
                    Err(error) => {
                        println!("Error: {}", error);
                    }
                }
                *eval_values[output_index]
                    .write()
                    .expect("Failed to acquire write lock") = ct_extract;
                vec_idx_by_gate_type.entry(curr_gate_type.clone()).and_modify(|ctr| {*ctr += 1});
            }
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }
        key_to_index
            .iter()
            .map(|(&key, &index)| (key.to_string(), eval_values[index].read().unwrap().clone()))
            .collect()
    }

    fn decrypt_outputs(
        &mut self,
        enc_wire_map: &HashMap<String, LweCiphertext32>,
        verbose: bool,
    ) -> HashMap<String, PtxtType> {
        let mut decrypted_outputs = HashMap::new();
        for output_wire in self.circuit.output_wires {
            let pt_extract = self.default_engine.decrypt_lwe_ciphertext(&self.host_client_key, &enc_wire_map[output_wire]).unwrap();
            let raw_pt_extract = self.default_engine.retrieve_plaintext(&pt_extract).unwrap();
            let output = raw_pt_extract < (1 << 31);
            decrypted_outputs.insert(output_wire.clone(), PtxtType::Bool(output));
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

        let eval_values = enc_wire_map
            .iter()
            .map(|(key, value)| (key.clone(), Arc::new(RwLock::new(value.clone()))))
            .collect::<HashMap<_, _>>();

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
                    .map(|input| eval_values[input].read().unwrap().clone())
                    .collect();
                let output_value = {
                    if gate.get_gate_type() == GateType::Lut {
                        gate.evaluate_encrypted_lut(&self.server_key, &mut input_values, cycle)
                    } else {
                        gate.evaluate_encrypted_dff(&input_values, cycle)
                    }
                };

                // Update the value of the corresponding key
                *eval_values[&gate.get_output_wire()]
                    .write()
                    .expect("Failed to acquire write lock") = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        eval_values
            .iter()
            .map(|(key, value)| (key.to_string(), value.read().unwrap().clone()))
            .collect::<HashMap<_, _>>()
    }

    fn decrypt_outputs(
        &mut self,
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
                    "u8" => FheType::U8(FheUint8::try_encrypt(0u8, &self.client_key).unwrap()),
                    "u16" => FheType::U16(FheUint16::try_encrypt(0u16, &self.client_key).unwrap()),
                    "u32" => FheType::U32(FheUint32::try_encrypt(0u32, &self.client_key).unwrap()),
                    "u64" => FheType::U64(FheUint64::try_encrypt(0u64, &self.client_key).unwrap()),
                    "u128" => {
                        FheType::U128(FheUint128::try_encrypt(0u128, &self.client_key).unwrap())
                    }
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
                "u8" => FheType::U8(FheUint8::try_encrypt(0u8, &self.client_key).unwrap()),
                "u16" => FheType::U16(FheUint16::try_encrypt(0u16, &self.client_key).unwrap()),
                "u32" => FheType::U32(FheUint32::try_encrypt(0u32, &self.client_key).unwrap()),
                "u64" => FheType::U64(FheUint64::try_encrypt(0u64, &self.client_key).unwrap()),
                "u128" => FheType::U128(FheUint128::try_encrypt(0u128, &self.client_key).unwrap()),
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

        let eval_values = enc_wire_map
            .iter()
            .map(|(key, value)| (key.clone(), Arc::new(RwLock::new(value.clone()))))
            .collect::<HashMap<_, _>>();

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
                                // Read the value of the corresponding key
                                ctxt_operand = eval_values[in_wire].read().unwrap().clone();
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
                            .map(|input| eval_values[input].read().unwrap().clone())
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

                // Update the value of the corresponding key
                *eval_values[&gate.get_output_wire()]
                    .write()
                    .expect("Failed to acquire write lock") = output_value;
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        rayon::broadcast(|_| unset_server_key());
        unset_server_key();

        eval_values
            .iter()
            .map(|(key, value)| (key.to_string(), value.read().unwrap().clone()))
            .collect::<HashMap<_, _>>()
    }

    fn decrypt_outputs(
        &mut self,
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

        let eval_values = enc_wire_map
            .iter()
            .map(|(key, value)| (key.clone(), Arc::new(RwLock::new(value.clone()))))
            .collect::<HashMap<_, _>>();

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
                    .map(|input| eval_values[input].read().unwrap().clone())
                    .collect();

                // Update the value of the corresponding key
                *eval_values[&gate.get_output_wire()]
                    .write()
                    .expect("Failed to acquire write lock") = gate
                    .evaluate_encrypted_high_precision_lut(
                        &self.wopbs_shortkey,
                        &self.wopbs_intkey,
                        &self.server_intkey,
                        &input_values,
                        cycle,
                    );
            });
            println!("  Evaluated gates in level [{}/{}]", level, total_levels);
        }

        eval_values
            .iter()
            .map(|(key, value)| (key.to_string(), value.read().unwrap().clone()))
            .collect::<HashMap<_, _>>()
    }

    fn decrypt_outputs(
        &mut self,
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
