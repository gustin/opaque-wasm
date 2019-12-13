use wasm_bindgen::prelude::*;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::Keypair;
use futures::{future, Future};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use js_sys::Promise;
use opaque::*;
use rand_os::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Sha3_512};
use std::panic;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::future_to_promise;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

#[derive(Debug, Serialize, Deserialize)]
pub struct Registration {
    pub beta: [u8; 32],
    pub v: [u8; 32],
    pub pub_s: [u8; 32],
}

#[wasm_bindgen]
extern "C" {
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
pub async fn registration_init(username: String, password: String) {
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
    let alpha_point: RistrettoPoint = hash_prime * r;

    //1. call registration 1 on a route with values
    // POST: /authenticate/
    // username
    // alpha
    // sign eventually?
    //    let (beta, v, pub_s) =
    //        registration_1(username, &alpha.compress().to_bytes());

    // POST username/alpha to http://localhost:8000/authenticate

    let alpha = alpha_point.compress().to_bytes();

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    let body = format!(
        r#"
        {{
            "username": "{}",
            "alpha": "{:?}"
        }}
        "#,
        username, alpha
    );
    opts.body(Some(&JsValue::from_str(&body)));

    let request = Request::new_with_str_and_init(
        "http://localhost:8000/authenticate/new",
        &opts,
    )
    .unwrap();

    /*    request
            .headers()
            .set("Content-Type", "application/json")
            .unwrap();
    */
    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

    let info: Registration = json.into_serde().unwrap();
    let js_value = JsValue::from_serde(&info).unwrap();
    /*
        let beta_point = CompressedRistretto::from_slice(&beta[..]);
        let beta = beta_point.decompress().unwrap();
        let v_point = CompressedRistretto::from_slice(&v[..]);
        let v = v_point.decompress().unwrap();

        alert(&format!("Rando: {:?}", keypair.secret.to_bytes()));

        let inverse_r = r.invert();
        let sub_beta = beta * inverse_r;

        let mut hasher = Sha3_512::new();
        // assuming multiple inputs create a unique hash not just concating, verse serializing
        hasher.input(password.as_bytes());
        hasher.input(v.compress().as_bytes());
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
     */
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
