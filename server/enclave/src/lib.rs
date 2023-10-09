#![crate_name = "sampleenclave"]
#![crate_type = "staticlib"]
#![feature(box_syntax)]
#![feature(core_intrinsics)]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(target_env = "sgx")]
extern crate core;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tunittest;

extern crate sgx_rand;
extern crate sgx_rand_derive;
extern crate sgx_serialize;

#[macro_use]
extern crate sgx_serialize_derive;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tseal;
extern crate sgx_types;

#[macro_use]
extern crate serde_derive;

extern crate base64;
extern crate bit_vec;
extern crate chrono;
extern crate http_req;
extern crate httparse;
extern crate itertools;
extern crate jsonwebtoken;
extern crate num_bigint;
extern crate rustls;
extern crate serde_json;
extern crate webpki;
extern crate webpki_roots;
extern crate yasna;

use sgx_types::*;
use std::prelude::v1::*;
use std::slice;
use std::string::String;
use std::sync::SgxMutex;
use std::collections::HashMap;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

mod auth;
mod rsa;
mod test;


lazy_static! {
    static ref JWK_INFO: SgxMutex<HashMap<i64, String>> = SgxMutex::new(HashMap::new());
}

#[no_mangle]
pub unsafe extern "C" fn init_tee() -> sgx_status_t {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Info)
        .init();

    test::test_all_function();

    match rsa::init_rsa_key() {
        Ok(_) => (),
        Err(x) => {
            error!("RSA key initialization failure.");
            return x;
        }
    };

    let x509_cert = match rsa::get_x509_cert() {
        Ok(x) => x,
        Err(x) => {
            error!("Unable to generate x509 certificate");
            return x;
        }
    };
    debug!("x509 cert: {}", x509_cert);

    match auth::update_config(auth::CONFIG_PATH) {
        Ok(()) => (),
        Err(x) => {
            error!("update config failed");
            return x;
        }
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_tee_jwks(
    tee_jwks: *mut u8,
    max_jwks_len: usize,
    tee_jwks_len: *mut usize,
) -> sgx_status_t {
    let mut jwk_info = JWK_INFO.lock().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    if jwk_info.len() == 0 {
        let jwk = rsa::get_tee_jwk().unwrap();
        let not_after = rsa::get_not_after().unwrap();
        jwk_info.insert(not_after, jwk.clone());
    } else {
        let mut key_remove: Vec<i64> = Vec::new();
        let mut vaild_jwk_num = 0;
        for not_after in jwk_info.keys() {
            if *not_after < now as i64 {
                key_remove.push(*not_after);
            } else if *not_after - rsa::ADVANCE_REFRESH_TIME > now as i64 {
                vaild_jwk_num = vaild_jwk_num + 1;
            }
        }

        // Remove invalid jwk
        for key in key_remove {
            jwk_info.remove(&key);
        }

        if vaild_jwk_num == 0 {
            let jwk = rsa::get_tee_jwk().unwrap();
            let not_after = rsa::get_not_after().unwrap();
            jwk_info.insert(not_after, jwk.clone());
        }
    }

    let mut tee_jwks_str: String = "".to_string();
    for value in jwk_info.values() {
        tee_jwks_str += &value;
        tee_jwks_str += &",".to_string();
    }
    tee_jwks_str.pop();

    let tee_jwks_string = format!(
        r#"{{"keys":[{}]}}"#, tee_jwks_str);

    if tee_jwks_string.len() > max_jwks_len {
        warn!(
            "jwks length over limit, actual length: {} limit max length:{}",
            tee_jwks_string.len(),
            max_jwks_len
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let raw_buf = unsafe {
        *tee_jwks_len = tee_jwks_string.len() as usize;
        slice::from_raw_parts_mut(tee_jwks as *mut u8, tee_jwks_string.len() as usize)
    };
    raw_buf.copy_from_slice(tee_jwks_string.as_bytes());

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_access_token(
    id_token: *const u8,
    id_token_len: usize,
    access_token: *mut u8,
    max_token_len: usize,
    access_token_len: *mut usize,
) -> sgx_status_t {
    // let mut jwk_endpoints: Vec<&str> = Vec::new();
    // jwk_endpoints.push("https://dev-f3qm0elg4mvfgpsu.us.auth0.com/.well-known/jwks.json");

    let id_token_slice = unsafe { slice::from_raw_parts(id_token, id_token_len) };
    let id_token: String = String::from_utf8(id_token_slice.to_vec()).unwrap();
    debug!("enclave: {}", id_token);
    let access_token_string = match auth::get_access_token(id_token) {
        Ok(x) => x,
        Err(_) => {
            warn!("Failed to get access token");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let mut jwk_info = JWK_INFO.lock().unwrap();
    let not_after = rsa::get_not_after().unwrap();
    if jwk_info.get(&not_after).is_none() {
        let jwk = rsa::get_tee_jwk().unwrap();
        jwk_info.insert(not_after, jwk.clone());
    }

    if access_token_string.len() > max_token_len {
        warn!(
            "Access token length over limit, actual length: {} limit max length:{}",
            access_token_string.len(),
            max_token_len
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let raw_buf = unsafe {
        *access_token_len = access_token_string.len() as usize;
        slice::from_raw_parts_mut(access_token as *mut u8, access_token_string.len() as usize)
    };
    raw_buf.copy_from_slice(access_token_string.as_bytes());

    sgx_status_t::SGX_SUCCESS
}