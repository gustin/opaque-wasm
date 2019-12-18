use wasm_bindgen::prelude::*;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Keypair, Signature};
use futures::{future, Future};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use js_sys::{Promise, JSON};
use opaque::sigma::KeyExchange;
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

macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegData {
    pub beta: [u8; 32],
    pub v: [u8; 32],
    pub pub_s: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthData {
    pub beta: [u8; 32],
    pub v: [u8; 32],
    pub envelope: Vec<u8>,
    pub key: Vec<u8>,
    pub y: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QrCode {
    pub qr_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthToken {
    pub auth_token: String,
}

#[wasm_bindgen]
pub fn setup() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
pub async fn register(username: String, password: String) {
    // => Registration 1
    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public.to_bytes();

    let r = Scalar::random(&mut cspring);
    let hash_prime =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha_point: RistrettoPoint = hash_prime * r;
    let alpha = alpha_point.compress().to_bytes();

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    let body = format!(
        r#"
        {{
            "username": "{}",
            "alpha": {:?}
        }}
        "#,
        username, alpha
    );
    opts.body(Some(&JsValue::from_str(&body)));

    let request = Request::new_with_str_and_init(
        "http://localhost:8000/plaintext/register/start",
        &opts,
    )
    .unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

    let j_string = JSON::stringify(&json).unwrap();
    log!("{:?}", j_string.as_string().unwrap());

    let result: RegData = json.into_serde().unwrap();
    log!("Beta: {:?}", result.beta);

    let beta_point = CompressedRistretto::from_slice(&result.beta[..]);
    let beta = beta_point.decompress().unwrap();
    let v_point = CompressedRistretto::from_slice(&result.v[..]);
    let v = v_point.decompress().unwrap();

    log!("Rando: {:?}", keypair.secret.to_bytes());

    let inverse_r = r.invert();
    let sub_beta = beta * inverse_r;

    let mut hasher = Sha3_512::new();
    // assuming multiple inputs create a unique hash not just concating, verse serializing
    hasher.input(password.as_bytes());
    hasher.input(v.compress().as_bytes());
    hasher.input(sub_beta.compress().to_bytes());
    let rwd_u = hasher.result();

    log!("-) RwdU: {:?}:", rwd_u);

    // => Registration 2

    let envelope = Envelope {
        priv_u: priv_u,
        pub_u: pub_u,
        pub_s: result.pub_s,
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

    log!("-) AuthEnv: AES-GCM-SIV Cipher Envelope {:?} :", env_cipher);

    // serialize from struct for safety
    let body = format!(
        r#"
        {{
            "username": "{}",
            "pub_u": {:?},
            "auth_env": {:?}
        }}
        "#,
        username, pub_u, env_cipher
    );
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    opts.body(Some(&JsValue::from_str(&body)));

    let request = Request::new_with_str_and_init(
        "http://localhost:8000/plaintext/register/finalize",
        &opts,
    )
    .unwrap();

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

    let j_string = JSON::stringify(&json).unwrap();
    log!("{:?}", j_string.as_string().unwrap());
}

#[wasm_bindgen]
pub async fn authenticate(username: String, password: String) -> String {
    //**
    // => Authentication 1
    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public.to_bytes();

    log!("Starting Authentication...");

    let r_a = Scalar::random(&mut cspring);
    let hash_prime_a =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha_point: RistrettoPoint = hash_prime_a * r_a;

    let x = Scalar::random(&mut cspring);
    let ke_1_point = RISTRETTO_BASEPOINT_POINT * x;
    let nA = "";
    //let sidA = 1;

    let alpha = alpha_point.compress().to_bytes();
    let ke_1 = ke_1_point.compress().to_bytes();

    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    let body = format!(
        r#"
        {{
            "username": "{}",
            "alpha": {:?},
            "key": {:?}
        }}
        "#,
        username, alpha, ke_1
    );
    opts.body(Some(&JsValue::from_str(&body)));

    log!("====> Authentication Start");
    let request = Request::new_with_str_and_init(
        "http://localhost:8000/plaintext/authenticate/start",
        &opts,
    )
    .unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

    let j_string = JSON::stringify(&json).unwrap();
    log!("{:?}", j_string.as_string().unwrap());

    let result: AuthData = json.into_serde().unwrap();
    log!("Beta: {:?}", result.beta);
    log!("V: {:?}", result.v);
    log!("Envelope: {:?}", result.envelope);
    log!("Key Exchange 2: {:?}", result.key);
    log!("Y: {:?}", result.y);

    // ==> Authenticate Final!!!
    let beta_point = CompressedRistretto::from_slice(&result.beta[..]);
    let beta_a = beta_point.decompress().unwrap();

    let v_point = CompressedRistretto::from_slice(&result.v[..]);
    let v_a = v_point.decompress().unwrap();

    let y_point = CompressedRistretto::from_slice(&result.y[..]);
    let y = y_point.decompress().unwrap();

    // OPRF

    log!("-) beta {:?}:", beta_a);
    log!("-) v {:?}:", v_a);
    log!("-) AuthEnv {:?}:", result.envelope);

    let inverse_r_a = r_a.invert();
    let sub_beta_a = beta_a * inverse_r_a;

    log!("-) {{1/r}} {:?}:", inverse_r_a);
    log!("-) beta^{{1/r}} {:?}:", sub_beta_a);

    log!("*) RwdU = H(x, v, beta^{{1/r}})");

    let mut hasher_a = Sha3_512::new();
    hasher_a.input(password.as_bytes()); // NOTE: Harden with a key derivitive, Section 3.4
    hasher_a.input(v_a.compress().to_bytes());
    hasher_a.input(sub_beta_a.compress().to_bytes());
    let rwd_u_a = hasher_a.result();

    log!("-) RwdU {:?}:", rwd_u_a);

    // Use rwd_u_a to decrypt envelope

    let hkdf_a = Hkdf::<Sha512>::new(None, &rwd_u_a);
    let mut okm_a = [0u8; 44]; // 32 byte key + 96 bit nonce
    let info_a = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(); // make info the domain string, +
    hkdf_a.expand(&info_a, &mut okm_a).unwrap();

    log!("-) HKDF OKM {}", hex::encode(&okm_a[..]));

    let encryption_key_a: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&okm_a[0..32]);
    let aead = Aes256GcmSiv::new(encryption_key_a);
    let nonce_a: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&okm_a[32..44]);

    log!("-) encryption key 32-byte {:?}:", encryption_key_a);
    log!("-) nonce 96 bit {:?}:", nonce_a);

    let envelope_decrypted = aead
        .decrypt(&nonce_a, result.envelope.as_slice())
        .expect("decryption failure");
    let envelope_for_realz: Envelope =
        bincode::deserialize(envelope_decrypted.as_slice()).unwrap();

    log!("=) EnvU (decoded) {:?}:", envelope_for_realz);

    // SIGMA

    //  KE3 = Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
    // { A, SIGa(g^y, g^x), MAC(Km; A) } Ke

    // decrypt ke_2
    let dh: RistrettoPoint = x * y;
    log!("-) Shared Secret: {:?}", dh);

    let hkdf = Hkdf::<Sha512>::new(None, dh.compress().as_bytes());
    let mut okm_dh = [0u8; 108]; // 32 byte key, 96 bit nonce, 64 bytes
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    hkdf.expand(&info, &mut okm_dh).unwrap();

    let encryption_key_dh: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&okm_dh[0..32]);
    let aead_dh = Aes256GcmSiv::new(encryption_key_dh);
    let nonce_dh: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&okm_dh[32..44]);

    log!("-) DH encryption key 32-byte {:?}:", encryption_key_dh);
    log!("-) DH nonce 96 bit {:?}:", nonce_dh);

    log!("* Decrypting: {:?}", result.key);
    // Guard: verify HMAC on B
    log!("* Slice: {:?}", result.key.as_slice());

    let key_2_decrypted = aead_dh
        .decrypt(&nonce_dh, result.key.as_slice())
        .expect("decryption failure");
    let key_2_for_realz: KeyExchange =
        bincode::deserialize(key_2_decrypted.as_slice()).unwrap();

    // SIGa(g^y, g^x)
    let mut prehashed: Sha3_512 = Sha3_512::new();
    prehashed.input(y.compress().as_bytes());
    prehashed.input(ke_1);
    let context: &[u8] = b"SpecificCustomerDomainName";
    let sig: Signature = keypair.sign_prehashed(prehashed, Some(context));

    // MAC(Km; PubS)
    let mut mac = HmacSha512::new_varkey(&okm_dh[44..108]).unwrap();
    mac.input(&pub_u);

    let key_exchange_3 = KeyExchange {
        identity: pub_u,
        signature: &sig.to_bytes(),
        mac: mac.result().code().as_slice().to_vec(),
    };

    let payload_dh: Vec<u8> = bincode::serialize(&key_exchange_3).unwrap();
    let encrypted_ke_3 =
        aead_dh.encrypt(&nonce_dh, payload_dh.as_slice()).unwrap();

    // sidA
    // sidB
    // { infoA, A, sigA(nB, sidA, g^x, infoA, infoA), MAC kM(A)} Ke

    //    let (beta_a, v_a, envelope_a) =
    //       authenticate_2(username, &alpha_a);
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    let body = format!(
        r#"
        {{
            "username": "{}",
            "key": {:?},
            "x": {:?}
        }}
        "#,
        username, encrypted_ke_3, ke_1
    );
    opts.body(Some(&JsValue::from_str(&body)));

    let request = Request::new_with_str_and_init(
        "http://localhost:8000/plaintext/authenticate/finalize",
        &opts,
    )
    .unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

    let j_string = JSON::stringify(&json).unwrap();
    log!("{:?}", j_string.as_string().unwrap());

    let result: AuthToken = json.into_serde().unwrap();
    result.auth_token
}

#[wasm_bindgen]
pub async fn second_factor(username: String) -> String {
    let mut opts = RequestInit::new();
    opts.method("POST");
    opts.mode(RequestMode::Cors);
    let body = format!(
        r#"
        {{
            "username": "{}"
        }}
        "#,
        username
    );
    opts.body(Some(&JsValue::from_str(&body)));

    let request = Request::new_with_str_and_init(
        "http://localhost:8000/plaintext/authenticate/second_factor",
        &opts,
    )
    .unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();
    let result: QrCode = json.into_serde().unwrap();
    result.qr_code
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
