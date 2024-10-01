use std::env;

use num::integer::lcm;
use num_bigint_dig::{BigUint, IntoBigUint, ModInverse, RandPrime};
use rand::prelude::*;

const BITS: usize = 1024;

fn main() {
    let message = env::args().nth(1).unwrap();
    let key_pair = RSAKeyPair::new(BITS);
    let private = key_pair.private;
    let public = key_pair.public;

    // println!("n:{} e:{}", public.n, public.e);
    // println!("d:{}", private.d);
    // println!("bitlenght: {}", public.n.bits());
    // let message = "This is a message".as_bytes();
    let message = BigUint::from_bytes_be(message.as_bytes());
    let c = message.modpow(&public.e, &public.n);
    let d = c.modpow(&private.d, &public.n);

    let c = unsafe { String::from_utf8_unchecked(c.to_bytes_be()) };
    let d = String::from_utf8(d.to_bytes_be()).unwrap();

    println!("Encrypted: {c}");
    println!("Decrypted: {d}");
}

struct RSAKeyPair {
    // pub size: usize,
    pub private: PrivateKey,
    pub public: PublicKey,
}

struct PrivateKey {
    d: BigUint,
}

struct PublicKey {
    n: BigUint,
    e: BigUint,
}

impl RSAKeyPair {
    fn new(bits: usize) -> RSAKeyPair {
        let mut rng = thread_rng();
        let p = rng.gen_prime(bits);
        let q = rng.gen_prime(bits);

        let n = p.clone() * q.clone();
        let lambn = lcm(p.clone() - 1u8, q.clone() - 1u8);
        let e: BigUint = 65537.into_biguint().unwrap();

        let d_int = e.clone().mod_inverse(lambn.clone()).unwrap();
        let d = match d_int.sign() {
            num_bigint_dig::Sign::Minus => {
                (lambn.clone() - (-d_int).to_biguint().unwrap()) % lambn.clone()
            }
            _ => d_int.into_biguint().unwrap(),
        };
        let private = PrivateKey { d };

        let public = PublicKey { n, e };

        RSAKeyPair {
            // size: bits,
            private,
            public,
        }
    }
}
