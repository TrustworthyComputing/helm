use tfhe::boolean::prelude::*;
use std::time::Instant;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let mut start = Instant::now();
    let (client_key, server_key) = gen_keys();
    println!("KeyGen done in {} seconds.", start.elapsed().as_secs_f64());

    // We use the client secret key to encrypt two messages:
    start = Instant::now();
    let ct_1 = client_key.encrypt(true);
    let ct_2 = client_key.encrypt(false);
    println!("Encryption done in {} seconds.", start.elapsed().as_secs_f64());

    // We use the server public key to execute a boolean circuit:
    // if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
    start = Instant::now();
    let ct_3 = server_key.not(&ct_2);
    let ct_4 = server_key.and(&ct_1, &ct_2);
    let ct_5 = server_key.nand(&ct_3, &ct_4);
    let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);
    println!("HE Eval done in {} seconds.", start.elapsed().as_secs_f64());

    // We use the client key to decrypt the output of the circuit:
    start = Instant::now();
    let output = client_key.decrypt(&ct_6);
    println!("Decryption done in {} seconds.", start.elapsed().as_secs_f64());

    assert_eq!(output, true);
}
