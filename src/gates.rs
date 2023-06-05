use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    vec,
};
use tfhe::{
    boolean::prelude::*,
    integer::{
        ciphertext::BaseRadixCiphertext, wopbs as WopbsInt, wopbs::WopbsKey as WopbsKeyInt,
        IntegerCiphertext, ServerKey as ServerKeyInt,
    },
    shortint::{
        ciphertext::{CiphertextBase, KeyswitchBootstrap},
        wopbs::WopbsKey as WopbsKeyShortInt,
        ServerKey as ServerKeyShortInt,
    },
};

#[derive(Clone, Debug, PartialEq)]
pub enum GateType {
    And,  // and  ID(in0, in1, out);
    Dff,  // dff  ID(in, ouevaluate_encryptedt);
    Lut,  // lut  ID(const, in0, ... , inN-1, out);
    Mux,  // mux  ID(in0, in1, sel, out);
    Nand, // nand ID(in0, in1, out);
    Nor,  // nor  ID(in0, in1, out);
    Not,  // not  ID(in, out);
    Or,   // or   ID(in0, in1, out);
    Xnor, // xnor ID(in0, in1, out);
    Xor,  // xor  ID(in0, in1, out);
}

#[derive(Clone)]
pub struct Gate {
    gate_name: String,
    gate_type: GateType,
    input_wires: Vec<String>,
    lut_const: Option<Vec<u64>>,
    output_wire: String,
    level: usize,
    cycle: usize,
    output: Option<bool>,
    encrypted_gate_output: Option<Ciphertext>,
    encrypted_lut_output: Option<CiphertextBase<KeyswitchBootstrap>>,
}

impl Eq for Gate {}

impl PartialEq for Gate {
    fn eq(&self, other: &Self) -> bool {
        self.gate_name == other.gate_name
    }
}

impl PartialOrd for Gate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.gate_name.partial_cmp(&other.gate_name)
    }
}

impl Ord for Gate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.gate_name.cmp(&other.gate_name)
    }
}

impl Hash for Gate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.gate_name.hash(state);
    }
}

impl fmt::Debug for Gate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}: {:?}({:?}) = {:?}({:?}). Level {}",
            self.gate_name,
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
        gate_name: String,
        gate_type: GateType,
        input_wires: Vec<String>,
        lut_const: Option<Vec<u64>>,
        output_wire: String,
        level: usize,
    ) -> Self {
        Gate {
            gate_name,
            gate_type,
            input_wires,
            lut_const,
            output_wire,
            level,
            cycle: 0,
            output: None,
            encrypted_gate_output: None,
            encrypted_lut_output: None,
        }
    }

    pub fn get_input_wires(&self) -> &Vec<String> {
        &self.input_wires
    }

    pub fn get_output_wire(&self) -> String {
        self.output_wire.clone()
    }

    pub fn get_gate_type(&self) -> GateType {
        self.gate_type.clone()
    }

    pub fn get_gate_name(&self) -> String {
        self.gate_name.clone()
    }

    pub fn set_level(&mut self, level: usize) {
        self.level = level;
    }

    pub fn evaluate(&mut self, input_values: &Vec<bool>, cycle: usize) -> bool {
        if let Some(output) = self.output {
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
                // Convert input bits to int:  [1, 1, 0, 1] => 13.
                for (input_idx, &input_val) in input_values.iter().enumerate() {
                    if input_val {
                        shift_amt += 1 << (end - input_idx);
                    }
                }
                // Convert integer LUT entry to bit array (multiple output wires)
                if !&self.lut_const.as_ref().unwrap().is_empty() {
                    (self.lut_const.as_ref().unwrap()[shift_amt] & 1) > 0
                } else {
                    panic!("Lut const not provided");
                }
            }
            GateType::Mux => {
                let select = input_values[2];
                (select && input_values[0]) || (!select && input_values[1])
            }
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

    pub fn evaluate_encrypted(
        &mut self,
        server_key: &ServerKey,
        input_values: &[Ciphertext],
        cycle: usize,
    ) -> Ciphertext {
        if let Some(encrypted_gate_output) = self.encrypted_gate_output.clone() {
            if self.cycle == cycle {
                return encrypted_gate_output;
            }
        }
        let encrypted_gate_output = match self.gate_type {
            GateType::And => server_key.and(&input_values[0], &input_values[1]),
            GateType::Dff => input_values[0].clone(),
            GateType::Lut => panic!("Can't mix LUTs with Boolean gates!"),
            GateType::Mux => server_key.mux(&input_values[2], &input_values[0], &input_values[1]),
            GateType::Nand => server_key.nand(&input_values[0], &input_values[1]),
            GateType::Nor => server_key.nor(&input_values[0], &input_values[1]),
            GateType::Not => server_key.not(&input_values[0]),
            GateType::Or => server_key.or(&input_values[0], &input_values[1]),
            GateType::Xnor => server_key.xnor(&input_values[0], &input_values[1]),
            GateType::Xor => server_key.xor(&input_values[0], &input_values[1]),
        };

        self.encrypted_gate_output = Some(encrypted_gate_output.clone());
        encrypted_gate_output
    }

    pub fn evaluate_encrypted_lut(
        &mut self,
        server_key: &ServerKeyShortInt,
        input_values: &Vec<CiphertextBase<KeyswitchBootstrap>>,
        cycle: usize,
    ) -> CiphertextBase<KeyswitchBootstrap> {
        if let Some(encrypted_lut_output) = self.encrypted_lut_output.clone() {
            if self.cycle == cycle {
                return encrypted_lut_output;
            }
        }

        lut(server_key, self.lut_const.as_ref().unwrap(), input_values)
    }

    pub fn evaluate_encrypted_high_precision_lut(
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

        high_precision_lut(
            wopbs_shortkey,
            wopbs_intkey,
            server_intkey,
            self.lut_const.as_ref().unwrap(),
            input_values,
        )
    }
}

// Shift the constant by ctxt amount
fn eval_luts(x: u64, lut_table: &Vec<u64>) -> u64 {
    lut_table[x as usize] & 1
}

pub fn lut(
    sks: &ServerKeyShortInt,
    lut_const: &Vec<u64>,
    ctxts: &Vec<CiphertextBase<tfhe::shortint::ciphertext::KeyswitchBootstrap>>,
) -> CiphertextBase<tfhe::shortint::ciphertext::KeyswitchBootstrap> {
    // Σ ctxts[i] * 2^i
    let ct_sum = ctxts
        .iter()
        .enumerate()
        .map(|(i, ct)| sks.scalar_mul(ct, 1 << (ctxts.len() - 1 - i)))
        .fold(sks.create_trivial(0), |acc, ct| sks.add(&acc, &ct));

    // Generate LUT entries from lut_const
    let lut = sks.generate_accumulator(|x| eval_luts(x, lut_const));

    // Eval PBS and return
    sks.apply_lookup_table(&ct_sum, &lut)
}

pub fn high_precision_lut(
    wk_si: &WopbsKeyShortInt,
    wk: &WopbsKeyInt,
    sks: &ServerKeyInt,
    lut_const: &Vec<u64>,
    ctxts: &Vec<CiphertextBase<tfhe::shortint::ciphertext::KeyswitchBootstrap>>,
) -> CiphertextBase<tfhe::shortint::ciphertext::KeyswitchBootstrap> {
    // Combine input ctxts into a radix ctxt
    let mut combined_vec = vec![];
    for block in ctxts {
        combined_vec.insert(0, block.clone());
    }
    let radix_ct =
        BaseRadixCiphertext::<CiphertextBase<KeyswitchBootstrap>>::from_blocks(combined_vec);

    // KS to WoPBS
    let radix_ct = wk.keyswitch_to_wopbs_params(sks, &radix_ct);

    // Generate LUT entries from lut_const
    let lut = generate_high_precision_lut_radix_helm(wk_si, &radix_ct, eval_luts, lut_const);

    // Eval PBS
    let radix_ct = wk.wopbs(&radix_ct, &lut);

    // KS to PBS
    let radix_ct = wk.keyswitch_to_pbs_params(&radix_ct);

    // Return LSB
    radix_ct.blocks().to_vec()[0].clone()
}

pub fn generate_high_precision_lut_radix_helm<F, T>(
    wk: &WopbsKeyShortInt,
    ct: &T,
    f: F,
    lut_entry: &Vec<u64>,
) -> Vec<Vec<u64>>
where
    F: Fn(u64, &Vec<u64>) -> u64,
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
    let delta = (1 << 63) / (wk.param.message_modulus.0 * wk.param.carry_modulus.0) as u64;

    for lut_index_val in 0..(1 << total_bit) {
        let encoded_with_deg_val = WopbsInt::encode_mix_radix(lut_index_val, &vec_deg_basis, basis);
        let decoded_val = WopbsInt::decode_radix(encoded_with_deg_val.clone(), basis);
        let f_val = f(decoded_val % modulus, lut_entry) % modulus;
        let encoded_f_val = WopbsInt::encode_radix(f_val, basis, block_nb as u64);
        for lut_number in 0..block_nb {
            vec_lut[lut_number][lut_index_val as usize] = encoded_f_val[lut_number] * delta;
        }
    }
    vec_lut
}