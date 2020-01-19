use futures::{future, Future};
use js_sys::{Promise, JSON};
use serde::{Deserialize, Serialize};
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
pub struct Challenge {
    pub challenge: String,
}


#[wasm_bindgen]
pub async fn webauthn_registration_challenge(username: String) -> String {
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
        "http://localhost:8000/plaintext/webauthn/registration_challenge",
        &opts,
        )
        .unwrap();

    let window = web_sys::window().unwrap();
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .unwrap();

    let resp: Response = resp_value.dyn_into().unwrap();
    let json = JsFuture::from(resp.json().unwrap()).await.unwrap();
    let result: Challenge = json.into_serde().unwrap();
    log!("{:?}",  result.challenge);
    result.challenge
}


// let value:  = serde_wasm_bindgen::from_value(value)?;
