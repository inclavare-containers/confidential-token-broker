
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

const RSA_KEY_PATH: &str = "RSA_KEY";

lazy_static! {
    static ref RSA_KEY_DATA: SgxMutex<Option<RSAKeyData>> = SgxMutex::new(None);
}
extern "C" {
    pub fn ocall_get_target_info(
        ret_val  : *mut sgx_status_t,
        ti       : *mut sgx_target_info_t
    ) -> sgx_status_t;

    pub fn ocall_generate_quote(
        ret_val        : *mut sgx_status_t,
        p_report       : *mut sgx_report_t,
        p_quote        : *mut u8,
        max_quote_len  : u32,
        p_quote_len    : *mut u32
    ) -> sgx_status_t;
}

fn write_rsa_key(path: &str) -> Result<(), sgx_status_t> {
    let helper = SerializeHelper::new();
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();

    let rsa_key_bytes = match helper.encode(rsa_key_data) {
        Some(d) => d,
        None => {
            println!("[-] Encode data failed.");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        },
    };
    
    let mut file = match SgxFile::create(path) {
        Ok(f) => f,
        Err(_) => {
            println!("[-] SgxFile::create failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        },
    };

    let write_size = match file.write(rsa_key_bytes.as_slice()) {
        Ok(len) => len,
        Err(_) => {
            println!("[-] SgxFile::write failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        },
    };

    println!("[+] File written successfully, write size: {}.", write_size);
    Ok(())
}

fn read_rsa_key(path: &str) -> Result<(), sgx_status_t> {
    let mut file = match SgxFile::open(path) {
        Ok(f) => f,
        Err(_) => {
            println!("[-] SgxFile::open failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        },
    };

    let mut data = Vec::with_capacity(1000);

    let read_size = match file.read_to_end(&mut data) {
        Ok(len) => len,
        Err(_) => {
            println!("[-] SgxFile::read failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_BAD_STATUS);
        },
    };

    if read_size == 0 {
        println!("[-] {} file is empty.", path);
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let helper = DeSerializeHelper::<RSAKeyData>::new(data);
    let rsa_key_data = match helper.decode() {
        Some(d) => d,
        None => {
            println!("[-] Decode data failed.");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        },
    };

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    // 5 minutes before the deadline still needs to update the key
    if (rsa_key_data.not_befer > now as i64) | (rsa_key_data.not_after - ADVANCE_REFRESH_TIME < now as i64) {
        println!("[-] Rsa key not in time range.");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let mut rsa_data = RSA_KEY_DATA.lock().unwrap();
    *rsa_data = Some(rsa_key_data);

    println!("[+] File read successfully, read size: {}.", read_size);
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
    println!("[+] Rsa key updated successfully!");

    write_rsa_key(path)?;
    Ok(())
}

fn init_rsa_key() -> Result<(), sgx_status_t> {
    match read_rsa_key(RSA_KEY_PATH) {
        Ok(_) => (),
        Err(_) => {
            println!("[+] Trying to generate a new RSA key.");
            update_rsa_key(RSA_KEY_PATH)?;
        }
    };

    println!("[+] init_rsa_key() success!");
    Ok(())
}

fn generate_quote() -> Option<Vec<u8>>{
    let mut rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    // 5 minutes before the deadline still needs to update the key
    if (rsa_key_data.not_befer < now as i64) | (rsa_key_data.not_after - ADVANCE_REFRESH_TIME < now as i64) {
        println!("[ENCLAVE] Rsa key not in time range. Generate new RSA key as quote customization data");
        match update_rsa_key(RSA_KEY_PATH) {
            Ok(_) => {
                rsa_key_data = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap()
            },
            Err(_) => return None
        };
    }

    let rsa3072_public_key = sgx_rsa3072_public_key_t {
        modulus: rsa_key_data.modulus.clone().try_into().unwrap(),
        exponent: rsa_key_data.e.clone().try_into().unwrap(),
    };

    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut ti : sgx_target_info_t = sgx_target_info_t::default();

    let result = unsafe {
        ocall_get_target_info(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut _)
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return None;
    }

    let mut public_key: Vec<u8> = Vec::new();
    public_key.extend(&rsa3072_public_key.modulus);
    public_key.extend(&rsa3072_public_key.exponent);

    let hash_public_key = rsgx_sha256_slice(public_key.as_slice()).unwrap();
    let mut data = [0; 64];
    data[..hash_public_key.len()].copy_from_slice(&hash_public_key);
    println!("[+] get Hash(rsa public key) for report");
    let report_data: sgx_report_data_t = sgx_report_data_t {
        d: data
    };
    let mut report = match rsgx_create_report(&ti, &report_data) {
        Ok(report) => report,
        Err(x) => {
            println!("[-] rsgx_create_report() failed, error code: {:?}", x);
            return None;
        }
    };

    const RET_QUOTE_BUF_LEN : u32 = 9999;
    let mut return_quote_buf : [u8; RET_QUOTE_BUF_LEN as usize] = [0;RET_QUOTE_BUF_LEN as usize];
    let mut quote_len : u32 = 0;

    let p_report = &mut report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let max_quote_len = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_generate_quote(
            &mut rt as *mut sgx_status_t,
            p_report,
            p_quote, 
            max_quote_len,
            p_quote_len)
    };
    match result {
        sgx_status_t::SGX_SUCCESS => (),
        _ => return None,
    };

    Some(return_quote_buf[0..quote_len as usize].to_vec())

}

#[no_mangle]
pub unsafe extern "C" fn run_server() -> sgx_status_t {
    match init_rsa_key() {
        Ok(_) => (),
        Err(x) => {
            println!("[-] RSA key initialization failure.");
            return x
        }
    };

    let quote = match generate_quote() {
        Some(x) => {
            println!("[+] Generate Quote successfully!");
            x
        },
        None => {
            println!("[-] Failed to generate quote");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    sgx_status_t::SGX_SUCCESS
}