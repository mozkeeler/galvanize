extern crate getopts;
extern crate ring;

use getopts::Options;
use ring::aead;
use ring::digest;
use ring::pbkdf2;
use ring::rand;
use ring::rand::SecureRandom;
use std::env;
use std::io::prelude::*;
use std::num::NonZeroU32;
use std::process;

// Adapted from https://doc.rust-lang.org/getopts/getopts/index.html
fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} <-e|-d> -p password", program);
    eprint!("{}", opts.usage(&brief));
}

fn derive_key(password: &str, key_out: &mut [u8]) {
    let salt = vec![0u8; 0];
    pbkdf2::derive(&digest::SHA256, NonZeroU32::new(1000).unwrap(), &salt, password.as_bytes(),
                   key_out);
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

fn encrypt_from_stdin(key: &[u8]) {
    let mut data = Vec::new();
    read_stdin(&mut data);
    let out_len = encrypt(key, &mut data);
    write_bytes(&data[..out_len]);
}

fn encrypt(key: &[u8], data: &mut Vec<u8>) -> usize {
    for _ in 0..aead::MAX_TAG_LEN {
        data.push(0);
    }
    let mut nonce = [0u8; aead::NONCE_LEN];
    let rng = rand::SystemRandom::new();
    assert!(rng.fill(&mut nonce).is_ok());
    write_bytes(&nonce);
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let seal_key = aead::SealingKey::new(&aead::AES_256_GCM, key).unwrap();
    let out_len = match aead::seal_in_place(&seal_key, nonce, aead::Aad::empty(), data,
                                            aead::MAX_TAG_LEN) {
        Ok(out_len) => out_len,
        Err(e) => {
            eprintln!("{}", e.to_string());
            process::exit(1);
        }
    };
    out_len
}

fn decrypt_from_stdin(key: &[u8]) {
    let mut data = Vec::new();
    read_stdin(&mut data);
    let out = decrypt(key, &mut data);
    write_bytes(out);
}

fn decrypt<'a>(key: &[u8], data: &'a mut Vec<u8>) -> &'a[u8] {
    let mut nonce = [0u8; aead::NONCE_LEN];
    for i in 0..NONCE_LEN {
      nonce[i] = data[i];
    }
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let open_key = aead::OpeningKey::new(&aead::AES_256_GCM, key).unwrap();
    let out = match aead::open_in_place(&open_key, nonce, aead::Aad::empty(), NONCE_LEN, data) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("{}", e.to_string());
            process::exit(1);
        }
    };
    out
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
            eprintln!("{}", e.to_string());
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
    if encrypt_specified && decrypt_specified {
        eprintln!("Can't specify both encrypt and decrypt.");
        print_usage(&program, opts);
        return;
    }

    if !encrypt_specified && !decrypt_specified {
        eprintln!("Either encrypt or decrypt must be specified.");
        print_usage(&program, opts);
        return;
    }

    if !matches.opt_present("p") {
        eprintln!("Must specify password.");
        print_usage(&program, opts);
        return;
    }

    let password = matches.opt_str("p").unwrap();
    let mut key = vec![0u8; digest::SHA256.output_len];
    derive_key(password.as_str(), &mut key);

    if encrypt_specified {
        encrypt_from_stdin(&key);
    } else {
        decrypt_from_stdin(&key);
    }
}
