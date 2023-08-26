use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    vec,
};
use tfhe::{
    boolean::prelude::*,
    integer::{
        ciphertext::BaseRadixCiphertext,
        wopbs as WopbsInt,
        wopbs::{IntegerWopbsLUT, WopbsKey as WopbsKeyInt},
        IntegerCiphertext, ServerKey as ServerKeyInt,
    },
    shortint::{
        wopbs::WopbsKey as WopbsKeyShortInt, Ciphertext as CiphertextBase,
        ServerKey as ServerKeyShortInt,
    },
    FheUint32,
};

#[derive(Clone, Debug, PartialEq)]
pub enum GateType {
    And,       // and  ID(in0, in1, out);
    Dff,       // dff  ID(in, out);
    Lut,       // lut  ID(const, in0, ... , inN-1, out);
    Mux,       // mux  ID(in0, in1, sel, out);
    Nand,      // nand ID(in0, in1, out);
    Nor,       // nor  ID(in0, in1, out);
    Not,       // not  ID(in, out);
    Or,        // or   ID(in0, in1, out);
    Xnor,      // xnor ID(in0, in1, out);
    Xor,       // xor  ID(in0, in1, out);
    Buf,       // buf  ID(in, out);
    ConstOne,  // one(out);
    ConstZero, // zero(out);
    Mult,      // mult ID(in0, in1, out);
    Add,       // add  ID(in0, in1, out);
    Sub,       // sub  ID(in0, in1, out);
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
    multibit_output: Option<u64>,
    encrypted_gate_output: Option<Ciphertext>,
    encrypted_lut_output: Option<CiphertextBase>,
    encrypted_multibit_output: Option<FheUint32>,
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
            multibit_output: None,
            encrypted_gate_output: None,
            encrypted_lut_output: None,
            encrypted_multibit_output: None,
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

    pub fn evaluate_multibit(&mut self, input_values: &[u64], cycle: usize) -> u64 {
        if let Some(multibit_output) = self.multibit_output {
            if self.cycle == cycle {
                return multibit_output;
            }
        }
        let multibit_output = {
            if self.gate_type == GateType::Mult {
                input_values.iter().product()
            } else if self.gate_type == GateType::Add {
                input_values.iter().sum()
            } else if self.gate_type == GateType::Sub {
                input_values.iter().fold(0, |diff, &x| diff - x)
            } else {
                0
            }
        };
        self.cycle = cycle;
        multibit_output
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
            GateType::Mult => input_values[0],
            GateType::Add => input_values[0],
            GateType::Sub => input_values[0],
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
            GateType::Buf => input_values[0],
            GateType::ConstOne => true,
            GateType::ConstZero => false,
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
            GateType::Add => panic!("Add gates can't be mixed with Boolean ops!"),
            GateType::Mult => panic!("Mult gates can't be mixed with Boolean ops!"),
            GateType::Sub => panic!("Sub gates can't be mixed with Boolean ops!"),
            GateType::Mux => server_key.mux(&input_values[2], &input_values[0], &input_values[1]),
            GateType::Nand => server_key.nand(&input_values[0], &input_values[1]),
            GateType::Nor => server_key.nor(&input_values[0], &input_values[1]),
            GateType::Not => server_key.not(&input_values[0]),
            GateType::Or => server_key.or(&input_values[0], &input_values[1]),
            GateType::Xnor => server_key.xnor(&input_values[0], &input_values[1]),
            GateType::Xor => server_key.xor(&input_values[0], &input_values[1]),
            GateType::Buf => input_values[0].clone(),
            GateType::ConstOne => server_key.trivial_encrypt(true),
            GateType::ConstZero => server_key.trivial_encrypt(false),
        };

        self.encrypted_gate_output = Some(encrypted_gate_output.clone());
        encrypted_gate_output
    }

    pub fn evaluate_encrypted_lut(
        &mut self,
        server_key: &ServerKeyShortInt,
        input_values: &Vec<CiphertextBase>,
        cycle: usize,
    ) -> CiphertextBase {
        if let Some(encrypted_lut_output) = self.encrypted_lut_output.clone() {
            if self.cycle == cycle {
                return encrypted_lut_output;
            }
        }

        lut(server_key, self.lut_const.as_ref().unwrap(), input_values)
    }

    pub fn evaluate_encrypted_mul_block(
        &mut self,
        ct1: &FheUint32,
        ct2: &FheUint32,
        cycle: usize,
    ) -> FheUint32 {
        if let Some(encrypted_multibit_output) = self.encrypted_multibit_output.clone() {
            if self.cycle == cycle {
                return encrypted_multibit_output;
            }
        }
        ct1 * ct2
    }

    pub fn evaluate_encrypted_mul_block_plain(
        &mut self,
        ct1: &FheUint32,
        pt1: u32,
        cycle: usize,
    ) -> FheUint32 {
        if let Some(encrypted_multibit_output) = self.encrypted_multibit_output.clone() {
            if self.cycle == cycle {
                return encrypted_multibit_output;
            }
        }
        ct1 * pt1
    }

    pub fn evaluate_encrypted_add_block(
        &mut self,
        ct1: &FheUint32,
        ct2: &FheUint32,
        cycle: usize,
    ) -> FheUint32 {
        if let Some(encrypted_multibit_output) = self.encrypted_multibit_output.clone() {
            if self.cycle == cycle {
                return encrypted_multibit_output;
            }
        }
        ct1 + ct2
    }

    pub fn evaluate_encrypted_add_block_plain(
        &mut self,
        ct1: &FheUint32,
        pt1: u32,
        cycle: usize,
    ) -> FheUint32 {
        if let Some(encrypted_multibit_output) = self.encrypted_multibit_output.clone() {
            if self.cycle == cycle {
                return encrypted_multibit_output;
            }
        }
        ct1 + pt1
    }

    pub fn evaluate_encrypted_sub_block(
        &mut self,
        ct1: &FheUint32,
        ct2: &FheUint32,
        cycle: usize,
    ) -> FheUint32 {
        if let Some(encrypted_multibit_output) = self.encrypted_multibit_output.clone() {
            if self.cycle == cycle {
                return encrypted_multibit_output;
            }
        }
        ct1 - ct2
    }

    pub fn evaluate_encrypted_sub_block_plain(
        &mut self,
        ct1: &FheUint32,
        pt1: u32,
        cycle: usize,
    ) -> FheUint32 {
        if let Some(encrypted_multibit_output) = self.encrypted_multibit_output.clone() {
            if self.cycle == cycle {
                return encrypted_multibit_output;
            }
        }
        ct1 - pt1
    }

    pub fn evaluate_encrypted_dff(
        &mut self,
        input_values: &[CiphertextBase],
        cycle: usize,
    ) -> CiphertextBase {
        if let Some(encrypted_lut_output) = self.encrypted_lut_output.clone() {
            if self.cycle == cycle {
                return encrypted_lut_output;
            }
        }
        let out = input_values[0].clone();
        self.encrypted_lut_output = Some(out.clone());
        out
    }

    pub fn evaluate_encrypted_high_precision_lut(
        &mut self,
        wopbs_shortkey: &WopbsKeyShortInt,
        wopbs_intkey: &WopbsKeyInt,
        server_intkey: &ServerKeyInt,
        input_values: &Vec<CiphertextBase>,
        cycle: usize,
    ) -> CiphertextBase {
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
    ctxts: &Vec<CiphertextBase>,
) -> CiphertextBase {
    // Σ ctxts[i] * 2^i
    let ct_sum = ctxts
        .iter()
        .enumerate()
        .map(|(i, ct)| sks.scalar_mul(ct, 1 << (ctxts.len() - 1 - i)))
        .fold(sks.create_trivial(0), |acc, ct| sks.add(&acc, &ct));

    // Generate LUT entries from lut_const
    let lut = sks.generate_lookup_table(|x| eval_luts(x, lut_const));

    // Eval PBS and return
    sks.apply_lookup_table(&ct_sum, &lut)
}

pub fn high_precision_lut(
    wk_si: &WopbsKeyShortInt,
    wk: &WopbsKeyInt,
    sks: &ServerKeyInt,
    lut_const: &Vec<u64>,
    ctxts: &Vec<CiphertextBase>,
) -> CiphertextBase {
    // Combine input ctxts into a radix ctxt
    let mut combined_vec = vec![];
    for block in ctxts {
        combined_vec.insert(0, block.clone());
    }
    let radix_ct = BaseRadixCiphertext::<CiphertextBase>::from_blocks(combined_vec);

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
) -> IntegerWopbsLUT
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
    let mut lut = IntegerWopbsLUT::new(
        tfhe::shortint::wopbs::PlaintextCount(lut_size),
        tfhe::shortint::wopbs::CiphertextCount(ct.blocks().len()),
    );

    let basis = ct.moduli()[0];
    let delta = (1 << 63) / (wk.param.message_modulus.0 * wk.param.carry_modulus.0) as u64;

    for lut_index_val in 0..(1 << total_bit) {
        let encoded_with_deg_val = WopbsInt::encode_mix_radix(lut_index_val, &vec_deg_basis, basis);
        let decoded_val = WopbsInt::decode_radix(encoded_with_deg_val.clone(), basis);
        let f_val = f(decoded_val % modulus, lut_entry) % modulus;
        let encoded_f_val = WopbsInt::encode_radix(f_val, basis, block_nb as u64);
        for (lut_number, radix_encoded_val) in encoded_f_val.iter().enumerate().take(block_nb) {
            lut.as_mut().get_small_lut_mut(lut_number).as_mut()[lut_index_val as usize] =
                radix_encoded_val * delta;
        }
    }
    lut
}
