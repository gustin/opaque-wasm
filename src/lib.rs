use wasm_bindgen::prelude::*;

use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Keypair};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opaque::*;
use rand_os::OsRng;
use sha2::Sha512;
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


    // => Registration 1

    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public.to_bytes();

    let r = Scalar::random(&mut cspring);
    let hash_prime =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha: RistrettoPoint = hash_prime * r;
    let (beta, v, pub_s) = registration_1(username, &alpha);

    alert(&format!("Rando: {:?}", keypair.secret.to_bytes()));

    let inverse_r = r.invert();
    let sub_beta = beta * inverse_r;

    let mut hasher = Sha3_512::new();
    // assuming multiple inputs create a unique hash not just concating, verse serializing
    hasher.input(password.as_bytes());
    hasher.input(v.compress().to_bytes());
    hasher.input(sub_beta.compress().to_bytes());
    let rwd_u = hasher.result();

    alert(&format!("-) RwdU: {:?}:", rwd_u));

    // => Registration 2

    let envelope = Envelope {
        priv_u: priv_u,
        pub_u: pub_u,
        pub_s: pub_s,
    };

    let hkdf = Hkdf::<Sha512>::new(None, &rwd_u);
    let mut output_key_material = [0u8; 44]; // 32 byte key + 96 bit nonce
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(); // NOTE: check info value
    hkdf.expand(&info, &mut output_key_material).unwrap();

    let encryption_key: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&output_key_material[0..32]);
    let aead = Aes256GcmSiv::new(encryption_key);
    let nonce: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&output_key_material[32..44]);

    let payload: Vec<u8> = bincode::serialize(&envelope).unwrap();
    let env_cipher = aead.encrypt(&nonce, payload.as_slice()).unwrap();

    alert(&format!("-) AuthEnv: AES-GCM-SIV Cipher Envelope {:?} :", env_cipher));


    // => Authentication 1

    let r_a = Scalar::random(&mut cspring);
    let hash_prime_a =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha_a: RistrettoPoint = hash_prime_a * r_a;

    let x = Scalar::random(&mut cspring);
    let ke_1 = RISTRETTO_BASEPOINT_POINT * x;
    let nA = "";
    let sidA = 1;

//    let (beta_a, v_a, envelope_a, ke_2, y) =
//        authenticate_1(username, &alpha_a, &ke_1);

//    let (beta_a, v_a, envelope_a) =
 //       authenticate_2(username, &alpha_a);
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
