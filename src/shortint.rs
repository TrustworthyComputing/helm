use tfhe::shortint::prelude::*;
use std::time::Instant;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let mut start = Instant::now();
    let (client_key, server_key) = gen_keys(Parameters::default());
    // let (client_key, server_key) = gen_keys(PARAM_MESSAGE_4_CARRY_4);
    println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

    // We use the client secret key to encrypt two messages:
    start = Instant::now();
    let msg1 = 3;
    let msg2 = 2;
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
    println!("Encryption done in {} seconds.", start.elapsed().as_secs_f64());

    // Do some HE computations
    start = Instant::now();
    let ct_add = server_key.unchecked_add(&ct_1, &ct_2);
    println!("Decryption done {} seconds.", start.elapsed().as_secs_f64());

    // Define the Hamming weight function
    // f: x -> sum of the bits of x
    let f = |x:u64| x.count_ones() as u64;

    // Generate the accumulator for the function
    let acc = server_key.generate_accumulator(f);

    let start_pbs = Instant::now();
    // Compute the function over the ciphertext using the PBS
    let ct_res = server_key.keyswitch_programmable_bootstrap(&ct_add, &acc);
    println!("PBS in {} seconds.", start_pbs.elapsed().as_secs_f64());
    println!("HE Eval done in {} seconds.", start.elapsed().as_secs_f64());

    // We use the client key to decrypt the output of the circuit:
    start = Instant::now();
    let output = client_key.decrypt(&ct_res);
    println!("Decryption done in {} seconds.", start.elapsed().as_secs_f64());
    
    assert_eq!(output, f(msg1 + msg2));
}
