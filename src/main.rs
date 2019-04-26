extern crate getopts;
extern crate ring;

use getopts::Options;
use ring::aead;
use ring::digest;
use ring::pbkdf2;
use ring::rand;
use std::env;
use std::io::prelude::*;
use std::process;

// Adapted from https://doc.rust-lang.org/getopts/getopts/index.html
fn print_usage(program: &str, opts: Options) {
    let mut stderr = std::io::stderr();
    let brief = format!("Usage: {} <-e|-d> -p password", program);
    write!(&mut stderr, "{}", opts.usage(&brief)).unwrap();
}

fn derive_key(password: &str, key_out: &mut [u8]) {
    let salt = vec![0u8; 0];
    pbkdf2::derive(&pbkdf2::HMAC_SHA256, 1000, &salt, password.as_bytes(), key_out);
}

fn read_stdin(buffer: &mut Vec<u8>) {
    let stdin = std::io::stdin();
    for byte in stdin.bytes() {
        buffer.push(byte.unwrap());
    }
}

fn write_bytes(data: &[u8]) {
    let mut stdout = std::io::stdout();
    assert!(stdout.write_all(data).is_ok());
}

const NONCE_LEN: usize = 96 / 8;

fn encrypt(key: &[u8]) {
    let mut data = Vec::new();
    read_stdin(&mut data);
    for _ in 0..aead::MAX_OVERHEAD_LEN {
        data.push(0);
    }
    let mut nonce = vec![0u8; NONCE_LEN];
    let rng = rand::SystemRandom::new();
    assert!(rng.fill(&mut nonce).is_ok());
    write_bytes(&nonce);
    let seal_key = aead::SealingKey::new(&aead::AES_256_GCM, key).unwrap();
    let ad = vec![0u8; 0];
    let out_len = match aead::seal_in_place(&seal_key, &nonce, &mut data, aead::MAX_OVERHEAD_LEN,
                                            &ad) {
        Ok(out_len) => out_len,
        Err(e) => {
            let mut stderr = std::io::stderr();
            writeln!(&mut stderr, "{}", e.to_string()).unwrap();
            process::exit(1);
        }
    };
    write_bytes(&data[..out_len]);
}

fn decrypt(key: &[u8]) {
    let mut data = Vec::new();
    read_stdin(&mut data);
    let mut nonce = Vec::new();
    for i in 0..NONCE_LEN {
      nonce.push(data[i]);
    }
    let open_key = aead::OpeningKey::new(&aead::AES_256_GCM, key).unwrap();
    let ad = vec![0u8; 0];
    let out_len = match aead::open_in_place(&open_key, &nonce, NONCE_LEN, &mut data, &ad) {
        Ok(out_len) => out_len,
        Err(e) => {
            let mut stderr = std::io::stderr();
            writeln!(&mut stderr, "{}", e.to_string()).unwrap();
            process::exit(1);
        }
    };
    write_bytes(&data[..out_len]);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("e", "encrypt", "encrypt stdin to stdout");
    opts.optflag("d", "decrypt", "decrypt stdin to stdout");
    opts.optflag("h", "help", "print this help message");
    opts.optopt("p", "password", "what password to use (with PBKDF2)", "");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            let mut stderr = std::io::stderr();
            writeln!(&mut stderr, "{}", e.to_string()).unwrap();
            print_usage(&program, opts);
            process::exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let encrypt_specified = matches.opt_present("e");
    let decrypt_specified = matches.opt_present("d");
    let mut stderr = std::io::stderr();
    if encrypt_specified && decrypt_specified {
        writeln!(&mut stderr, "Can't specify both encrypt and decrypt.").unwrap();
        print_usage(&program, opts);
        return;
    }

    if !encrypt_specified && !decrypt_specified {
        writeln!(&mut stderr, "Either encrypt or decrypt must be specified.").unwrap();
        print_usage(&program, opts);
        return;
    }

    if !matches.opt_present("p") {
        writeln!(&mut stderr, "Must specify password.").unwrap();
        print_usage(&program, opts);
        return;
    }

    let password = matches.opt_str("p").unwrap();
    let mut key = vec![0u8; digest::SHA256.output_len];
    derive_key(password.as_str(), &mut key);

    if encrypt_specified {
        encrypt(&key);
    } else {
        decrypt(&key);
    }
}
