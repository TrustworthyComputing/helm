use std::time::Instant;
use tfhe::{
    integer::{
        ciphertext::BaseRadixCiphertext, wopbs as WopbsInt, wopbs::WopbsKey as WopbsKeyInt,
        ClientKey as ClientKeyInt, IntegerCiphertext, ServerKey as ServerKeyInt,
    },
    shortint as ShortInt,
    shortint::{
        ciphertext::{CiphertextBase, KeyswitchBootstrap},
        parameters::{
            parameters_wopbs_message_carry::WOPBS_PARAM_MESSAGE_1_CARRY_1, PARAM_MESSAGE_1_CARRY_1,
        },
        wopbs::WopbsKey as WopbsKeyShortInt,
    },
};

pub fn generate_lut_radix_helm<F, T>(
    wk: &WopbsKeyShortInt,
    ct: &T,
    f: F,
    lut_entries: &Vec<u64>,
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
    let delta: u64 = (1 << 63) / (wk.param.message_modulus.0 * wk.param.carry_modulus.0) as u64;

    for lut_index_val in 0..(1 << total_bit) {
        let encoded_with_deg_val = WopbsInt::encode_mix_radix(lut_index_val, &vec_deg_basis, basis);
        let decoded_val = WopbsInt::decode_radix(encoded_with_deg_val.clone(), basis);
        let f_val = f(decoded_val % modulus, lut_entries) % modulus;
        let encoded_f_val = WopbsInt::encode_radix(f_val, basis, block_nb as u64);
        for lut_number in 0..block_nb {
            vec_lut[lut_number][lut_index_val as usize] = encoded_f_val[lut_number] * delta;
        }
    }
    vec_lut
}

// Shift the constant by ctxt amount
fn eval_luts(x: u64, lut_entries: &Vec<u64>) -> u64 {
    ((lut_entries[0] >> x) & 1) + (((lut_entries[1] >> x) & 1) << 1)
}

fn main() {
    // Generate the client key and the server key:
    let (cks_shortint, sks_shortint) = ShortInt::gen_keys(PARAM_MESSAGE_1_CARRY_1); // single bit ctxt
    let cks = ClientKeyInt::from(cks_shortint.clone());
    let sks = ServerKeyInt::from_shortint(&cks, sks_shortint.clone());

    let wopbs_key_shortint = WopbsKeyShortInt::new_wopbs_key(
        &cks_shortint,
        &sks_shortint,
        &WOPBS_PARAM_MESSAGE_1_CARRY_1,
    );
    let wopbs_key = WopbsKeyInt::from(wopbs_key_shortint.clone());

    let nb_block = 6;
    let moduli = cks.parameters().message_modulus.0 << (nb_block - 1) as u64;
    println!("Num blocks: {}", nb_block);
    println!("Moduli: {}", moduli);

    let lut_entries = vec![0xf880077f077ff880u64, 0xcca18122c0aedabd];

    let clear = 12;
    let ct = cks.encrypt_radix(clear, nb_block);
    let ct = wopbs_key.keyswitch_to_wopbs_params(&sks, &ct);
    let mut start = Instant::now();
    // let lut = wopbs_key.generate_lut_radix(&ct, eval_luts);
    let lut = generate_lut_radix_helm(&wopbs_key_shortint, &ct, eval_luts, &lut_entries);
    println!(
        "Generate LUT radix: {} seconds.",
        start.elapsed().as_secs_f64()
    );
    start = Instant::now();
    let ct_res = wopbs_key.wopbs(&ct, &lut);
    println!("Compute PBS: {} seconds.", start.elapsed().as_secs_f64());
    let mut combined_vec = vec![];
    for block in ct_res.blocks().iter() {
        combined_vec.insert(0, block.clone());
    }
    let mut enc_bit_rev =
        BaseRadixCiphertext::<CiphertextBase<KeyswitchBootstrap>>::from_blocks(combined_vec);

    let ct_res = wopbs_key.keyswitch_to_pbs_params(&ct_res);
    enc_bit_rev = wopbs_key.keyswitch_to_pbs_params(&enc_bit_rev);

    let res: u64 = cks.decrypt_radix(&ct_res);
    let rev_res: u64 = cks.decrypt_radix(&enc_bit_rev);
    println!("rev_res: {:#06b}", rev_res);
    println!("res: {:#08b}", res);
    // println!("bits: {}{}{}{}{}{}", bit_0, bit_1, bit_2, bit_3, bit_4, bit_5);
    assert_eq!(res, eval_luts(clear, &lut_entries) % moduli as u64);
}
