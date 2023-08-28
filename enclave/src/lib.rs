
#![crate_name = "sampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_rand_derive;
extern crate sgx_serialize;

#[macro_use]
extern crate sgx_serialize_derive;

#[macro_use]
extern crate lazy_static;

extern crate sgx_types;
extern crate sgx_tseal;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;

extern crate rustls;
extern crate webpki;
extern crate webpki_roots;
extern crate itertools;
extern crate base64;
extern crate httparse;
extern crate yasna;
extern crate bit_vec;
extern crate num_bigint;
extern crate chrono;

use std::sgxfs::SgxFile;
use std::io::{Read, Write};

use sgx_serialize::{SerializeHelper, DeSerializeHelper};

use std::prelude::v1::*;
use std::time::*;

use sgx_types::*;
use sgx_tcrypto::*;
use std::time::SystemTime;
use std::untrusted::time::SystemTimeEx;
use std::str;
use std::vec::Vec;
use std::convert::TryInto;
use std::string::String;
use std::sync::SgxMutex;

use num_bigint::BigUint;
use bit_vec::BitVec;
use yasna::models::ObjectIdentifier;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;

use sgx_tse::rsgx_create_report;

const CERTEXPIRYDAYS: i64 = 90i64;
const ISSUER : &str = "confidential-token-broker";
const SUBJECT : &str = "confidential-token-broker";

#[derive(Serializable, DeSerializable, Clone, Default, Debug)]
struct RSAKeyData {
    modulus: Vec<u8>,
    d: Vec<u8>,
    e: Vec<u8>,
    not_befer: time_t,
    not_after: time_t,
}

// const RSA_DURATION: u64 = 604800;
const RSA_DURATION: u64 = 330;
const ADVANCE_REFRESH_TIME: i64 = 300;

lazy_static! {
    static ref RSA_KEY_DATA: SgxMutex<Option<RSAKeyData>> = SgxMutex::new(None);
}
// extern "C" {
//     pub fn ocall_get_target_info(
//         ret_val  : *mut sgx_status_t,
//         ti       : *mut sgx_target_info_t
//     ) -> sgx_status_t;

//     pub fn ocall_generate_quote(
//         ret_val        : *mut sgx_status_t,
//         p_report       : *mut sgx_report_t,
//         p_quote        : *mut u8,
//         max_quote_len  : u32,
//         p_quote_len    : *mut u32
//     ) -> sgx_status_t;
// }

fn write_rsa_key(path: &str) -> Result<(), sgx_status_t> {
    let helper = SerializeHelper::new();
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();

    let rsa_key_bytes = match helper.encode(rsa_key_data) {
        Some(d) => d,
        None => {
            println!("Encode data failed.");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        },
    };
    
    let mut file = match SgxFile::create(path) {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::create failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        },
    };

    let write_size = match file.write(rsa_key_bytes.as_slice()) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::write failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        },
    };

    println!("File written successfully, write size: {}.", write_size);
    Ok(())
}

fn read_rsa_key(path: &str) -> Result<(), sgx_status_t> {
    let mut file = match SgxFile::open(path) {
        Ok(f) => f,
        Err(_) => {
            println!("SgxFile::open failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        },
    };

    let mut data = Vec::with_capacity(1000);

    let read_size = match file.read_to_end(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("SgxFile::read failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_BAD_STATUS);
        },
    };

    if read_size == 0 {
        println!("{} file is empty.", path);
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let helper = DeSerializeHelper::<RSAKeyData>::new(data);
    let rsa_key_data = match helper.decode() {
        Some(d) => d,
        None => {
            println!("Decode data failed.");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        },
    };

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    // 5 minutes before the deadline still needs to update the key
    if (rsa_key_data.not_befer > now as i64) | (rsa_key_data.not_after - ADVANCE_REFRESH_TIME < now as i64) {
        println!("Rsa key not in time range.");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let mut rsa_data = RSA_KEY_DATA.lock().unwrap();
    *rsa_data = Some(rsa_key_data);

    println!("File read successfully, read size: {}.", read_size);
    Ok(())
}

fn update_rsa_key(path: &str) -> Result<(), sgx_status_t> {

    let mut n: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE];
    let mut d: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut q: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];

    rsgx_create_rsa_key_pair(SGX_RSA3072_KEY_SIZE as i32,
                            SGX_RSA3072_PUB_EXP_SIZE as i32,
                            n.as_mut_slice(),
                            d.as_mut_slice(),
                            e.as_mut_slice(),
                            p.as_mut_slice(),
                            q.as_mut_slice(),
                            dmp1.as_mut_slice(),
                            dmq1.as_mut_slice(),
                            iqmp.as_mut_slice())?;

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

    {
        let mut rsa_data = RSA_KEY_DATA.lock().unwrap();
        *rsa_data = Some(RSAKeyData {
                    modulus: n.clone().try_into().unwrap(),
                    d: d.clone().try_into().unwrap(),
                    e: e.clone().try_into().unwrap(),
                    not_befer: now as time_t,
                    not_after: (now + RSA_DURATION) as time_t,
                });
    }

    write_rsa_key(path)?;

    println!("Rsa key updated successfully !");
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn init_rsa_key() -> sgx_status_t {
    let rsa_key_path = "RSA_KEY";

    match read_rsa_key(rsa_key_path) {
        Ok(_) => (),
        Err(_) => {
            match update_rsa_key(rsa_key_path) {
                Ok(_) => (),
                Err(x) => return x
            };
        }
    };

    println!("[ENCLAVE] init_rsa_key() success!");
    sgx_status_t::SGX_SUCCESS
}