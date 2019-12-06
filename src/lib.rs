use wasm_bindgen::prelude::*;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Keypair};
use opaque::*;
use rand_os::OsRng;
use sha3::{Digest, Sha3_512};
use std::panic;

#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

#[wasm_bindgen]
pub fn init() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
pub fn registration_init(username: &str, password: &str) {
    // opaque client code, call function in lib for now
    // client_registration_values
    // then package and post to a url
    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public.to_bytes();

    let r = Scalar::random(&mut cspring);
    let hash_prime =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha: RistrettoPoint = hash_prime * r;
    let (beta, v, pub_s) = registration_1(username, &alpha);

    alert(&format!("Beta, {:?}!", beta));
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
