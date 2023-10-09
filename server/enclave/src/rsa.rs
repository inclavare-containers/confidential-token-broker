use bit_vec::BitVec;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;
use num_bigint::BigUint;
use sgx_serialize::{DeSerializeHelper, SerializeHelper};
use sgx_tcrypto::*;
use sgx_tse::rsgx_create_report;
use sgx_types::*;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::prelude::v1::*;
use std::sgxfs::SgxFile;
use std::str;
use std::string::String;
use std::sync::SgxMutex;
use std::time::SystemTime;
use std::time::*;
use std::vec::Vec;
use yasna::models::ObjectIdentifier;

use std::untrusted::fs::remove_file;

const ISSUER: &str = "confidential-token-broker";
const SUBJECT: &str = "confidential-token-broker";

#[derive(Serializable, DeSerializable, Clone, Default, Debug)]
struct RSAKeyData {
    modulus: Vec<u8>,
    d: Vec<u8>,
    e: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
    dmp1: Vec<u8>,
    dmq1: Vec<u8>,
    iqmp: Vec<u8>,
    not_befer: time_t,
    not_after: time_t,
}

pub const RSA_DURATION: i64 = 60 * 60 * 24 * 90;
pub const ADVANCE_REFRESH_TIME: i64 = 60 * 60 * 2;
const RSA_KEY_PATH: &str = "RSA_KEY";

lazy_static! {
    static ref RSA_KEY_DATA: SgxMutex<Option<RSAKeyData>> = SgxMutex::new(None);
}
extern "C" {
    pub fn ocall_get_target_info(
        ret_val: *mut sgx_status_t,
        ti: *mut sgx_target_info_t,
    ) -> sgx_status_t;

    pub fn ocall_generate_quote(
        ret_val: *mut sgx_status_t,
        p_report: *mut sgx_report_t,
        p_quote: *mut u8,
        max_quote_len: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

fn write_rsa_key(path: &str) -> SgxError {
    info!("Call write_rsa_key()");
    let helper = SerializeHelper::new();
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();

    let rsa_key_bytes = match helper.encode(rsa_key_data) {
        Some(d) => d,
        None => {
            error!("Encode data failed.");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    let mut file = match SgxFile::create(path) {
        Ok(f) => f,
        Err(_) => {
            error!("SgxFile::create failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        }
    };

    let write_size = match file.write(rsa_key_bytes.as_slice()) {
        Ok(len) => len,
        Err(_) => {
            error!("SgxFile::write failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        }
    };

    info!("File written successfully, write size: {}.", write_size);
    Ok(())
}

fn read_rsa_key(path: &str) -> SgxError {
    info!("Call read_rsa_key()");

    let mut file = match SgxFile::open(path) {
        Ok(f) => f,
        Err(_) => {
            warn!("SgxFile::open failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE);
        }
    };

    let mut data = Vec::with_capacity(1000);

    let read_size = match file.read_to_end(&mut data) {
        Ok(len) => len,
        Err(_) => {
            warn!("SgxFile::read failed.");
            return Err(sgx_status_t::SGX_ERROR_FILE_BAD_STATUS);
        }
    };

    if read_size == 0 {
        warn!("{} file is empty.", path);
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let helper = DeSerializeHelper::<RSAKeyData>::new(data);
    let rsa_key_data = match helper.decode() {
        Some(d) => d,
        None => {
            warn!("Decode data failed.");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // 5 minutes before the deadline still needs to update the key
    if (rsa_key_data.not_befer > now as i64)
        | (rsa_key_data.not_after - ADVANCE_REFRESH_TIME < now as i64)
    {
        warn!("Rsa key not in time range.");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let mut rsa_data = RSA_KEY_DATA.lock().unwrap();
    *rsa_data = Some(rsa_key_data);

    info!("File read successfully, read size: {}.", read_size);
    Ok(())
}

fn update_rsa_key(path: &str) -> SgxError {
    info!("Call update_rsa_key()");

    let mut n: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE];
    let mut d: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut q: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; SGX_RSA3072_KEY_SIZE / 2];

    rsgx_create_rsa_key_pair(
        SGX_RSA3072_KEY_SIZE as i32,
        SGX_RSA3072_PUB_EXP_SIZE as i32,
        n.as_mut_slice(),
        d.as_mut_slice(),
        e.as_mut_slice(),
        p.as_mut_slice(),
        q.as_mut_slice(),
        dmp1.as_mut_slice(),
        dmq1.as_mut_slice(),
        iqmp.as_mut_slice(),
    )?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    {
        let mut rsa_data = RSA_KEY_DATA.lock().unwrap();
        *rsa_data = Some(RSAKeyData {
            modulus: n.clone().try_into().unwrap(),
            d: d.clone().try_into().unwrap(),
            e: e.clone().try_into().unwrap(),
            p: p.clone().try_into().unwrap(),
            q: q.clone().try_into().unwrap(),
            dmp1: dmp1.clone().try_into().unwrap(),
            dmq1: dmq1.clone().try_into().unwrap(),
            iqmp: iqmp.clone().try_into().unwrap(),
            not_befer: now as time_t,
            not_after: (now as i64 + RSA_DURATION) as time_t,
        });
    }

    write_rsa_key(path)?;
    Ok(())
}

pub fn get_base64url_rsa_data_sha256() -> SgxResult<String> {
    let helper = SerializeHelper::new();
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();
    let rsa_key_bytes = match helper.encode(rsa_key_data) {
        Some(d) => d,
        None => {
            error!("Encode data failed.");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };
    let rsa_data_sha256 = rsgx_sha256_slice(rsa_key_bytes.as_slice())?;
    Ok(base64::encode(rsa_data_sha256))
}

pub fn get_base64url_n() -> SgxResult<String> {
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();
    let mut n = rsa_key_data.modulus.clone();
    n.reverse();
    let big_num_n = BigUint::from_bytes_be(n.as_slice()).to_bytes_be();
    Ok(base64::encode_config(big_num_n, base64::URL_SAFE_NO_PAD))
}

pub fn get_base64url_e() -> SgxResult<String> {
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();
    let mut e = rsa_key_data.e.clone();
    e.reverse();
    let big_num_e = BigUint::from_bytes_be(e.as_slice()).to_bytes_be();
    Ok(base64::encode_config(big_num_e, base64::URL_SAFE_NO_PAD))
}

pub fn get_not_after() -> SgxResult<time_t> {
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();
    Ok(rsa_key_data.not_after)
}

pub fn get_rsa_private_key_pem() -> SgxResult<String> {
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();

    let rsa_key_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(0);
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));
                writer.next().write_null();
            });
            let rsa_key = yasna::construct_der(|writer| {
                let mut modulus = rsa_key_data.modulus.clone();
                modulus.reverse();
                let mut e = rsa_key_data.e.clone();
                e.reverse();
                let mut d = rsa_key_data.d.clone();
                d.reverse();
                let mut p = rsa_key_data.p.clone();
                p.reverse();
                let mut q = rsa_key_data.q.clone();
                q.reverse();
                let mut dmp1 = rsa_key_data.dmp1.clone();
                dmp1.reverse();
                let mut dmq1 = rsa_key_data.dmq1.clone();
                dmq1.reverse();
                let mut iqmp = rsa_key_data.iqmp.clone();
                iqmp.reverse();
                writer.write_sequence(|writer| {
                    writer.next().write_u8(0);
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(modulus.as_slice()));
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(e.as_slice()));
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(d.as_slice()));
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(p.as_slice()));
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(q.as_slice()));
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(dmp1.as_slice()));
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(dmq1.as_slice()));
                    writer
                        .next()
                        .write_biguint(&BigUint::from_bytes_be(iqmp.as_slice()));
                });
            });
            writer.next().write_bytes(&rsa_key);
        });
    });
    let rsa_private_key = base64::encode(rsa_key_der);
    // add PEM header and ending
    let rsa_private_key_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        rsa_private_key
    );

    Ok(rsa_private_key_pem)
}

fn generate_quote() -> SgxResult<Vec<u8>> {
    info!("Call generate_quote()");

    // let mut rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();

    // let now = SystemTime::now()
    //     .duration_since(SystemTime::UNIX_EPOCH)
    //     .unwrap()
    //     .as_secs();
    // 2 hours before the deadline still needs to update the key
    // if (rsa_key_data.not_befer > now as i64)
    //     | (rsa_key_data.not_after - ADVANCE_REFRESH_TIME < now as i64)
    // {
    //     warn!("Rsa key not in time range. Generate new RSA key as quote customization data");
    //     match update_rsa_key(RSA_KEY_PATH) {
    //         Ok(_) => rsa_key_data = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap(),
    //         Err(x) => {
    //             error!("update_rsa_key() failed for quote");
    //             return Err(x);
    //         }
    //     };
    // }

    // let rsa3072_public_key = sgx_rsa3072_public_key_t {
    //     modulus: rsa_key_data.modulus.clone().try_into().unwrap(),
    //     exponent: rsa_key_data.e.clone().try_into().unwrap(),
    // };

    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();

    let result = unsafe { ocall_get_target_info(&mut rt as *mut sgx_status_t, &mut ti as *mut _) };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let public_key = format!("{{n: {}, e: {}}}", get_base64url_n().unwrap(), get_base64url_e().unwrap());
    debug!("{:?}", public_key.clone());
    // let mut public_key: Vec<u8> = Vec::new();
    // public_key.extend(&rsa3072_public_key.modulus);
    // public_key.extend(&rsa3072_public_key.exponent);

    let hash_public_key = rsgx_sha256_slice(public_key.as_bytes()).unwrap();
    let mut data = [0; 64];
    data[..hash_public_key.len()].copy_from_slice(&hash_public_key);
    debug!("Hash(Rsa Public Key) : {:?}", data);
    let report_data: sgx_report_data_t = sgx_report_data_t { d: data };
    let mut report = match rsgx_create_report(&ti, &report_data) {
        Ok(report) => report,
        Err(x) => {
            error!("rsgx_create_report() failed, error code: {:?}", x);
            return Err(x);
        }
    };

    const RET_QUOTE_BUF_LEN: u32 = 9999;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

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
            p_quote_len,
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => (),
        other => return Err(other),
    };

    Ok(return_quote_buf[0..quote_len as usize].to_vec())
}

pub fn get_x509_cert() -> SgxResult<String> {
    let quote = generate_quote()?;

    info!("Call get_x509_cert()");
    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();
    let rsa3072_key = sgx_rsa3072_key_t {
        modulus: rsa_key_data.modulus.clone().try_into().unwrap(),
        d: rsa_key_data.d.clone().try_into().unwrap(),
        e: rsa_key_data.e.clone().try_into().unwrap(),
    };

    // Generate Certificate DER
    let cert_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                // Certificate Version
                writer
                    .next()
                    .write_tagged(yasna::Tag::context(0), |writer| {
                        writer.write_i8(2);
                    });
                // Certificate Serial Number (unused but required)
                writer.next().write_u8(1);
                // Signature Algorithm: rsa-with-SHA256
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                        1, 2, 840, 113549, 1, 1, 11,
                    ]));
                });
                // Issuer: CN=confidential-token-broker (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                            writer.next().write_utf8_string(&ISSUER);
                        });
                    });
                });
                // Validity: Issuing/Expiring Time (unused but required)
                // let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let issue_ts = TzUtc.timestamp(rsa_key_data.not_befer as i64, 0);
                let expire_ts = TzUtc.timestamp(rsa_key_data.not_after as i64, 0);
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_utctime(&yasna::models::UTCTime::from_datetime(&issue_ts));
                    writer
                        .next()
                        .write_utctime(&yasna::models::UTCTime::from_datetime(&expire_ts));
                });
                // Subject: CN=confidential-token-broker (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                            writer.next().write_utf8_string(&SUBJECT);
                        });
                    });
                });
                // SubjectPublicKeyInfo
                writer.next().write_sequence(|writer| {
                    // Public Key Algorithm
                    writer.next().write_sequence(|writer| {
                        // id-rsaPublicKey
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                            1, 2, 840, 113549, 1, 1, 1,
                        ]));
                        writer.next().write_null();
                    });
                    // RSA Public Key
                    let sig_der = yasna::construct_der(|writer| {
                        writer.write_sequence(|writer| {
                            // modulus and e
                            let mut n = rsa3072_key.modulus.to_vec().clone();
                            let mut e = rsa3072_key.e.to_vec().clone();
                            n.reverse();
                            e.reverse();
                            let big_num_n = BigUint::from_bytes_be(n.as_slice()).to_bytes_be();
                            let big_num_e = BigUint::from_bytes_be(e.as_slice()).to_bytes_be();

                            writer
                                .next()
                                .write_biguint(&BigUint::from_bytes_be(big_num_n.as_slice()));
                            writer
                                .next()
                                .write_biguint(&BigUint::from_bytes_be(big_num_e.as_slice()));
                        });
                    });
                    writer.next().write_bitvec(&BitVec::from_bytes(&sig_der));
                });
                // Certificate V3 Extension
                writer
                    .next()
                    .write_tagged(yasna::Tag::context(3), |writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                                    1, 2, 840, 113741, 1, 13, 1,
                                ]));
                                writer.next().write_bytes(&quote);
                            });
                        });
                    });
            });
            // Signature Algorithm: rsa-with-SHA256
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                    1, 2, 840, 113549, 1, 1, 11,
                ]));
            });
            // Signature
            let sig = {
                let tbs = &writer.buf[4..];
                rsgx_rsa3072_sign_slice(tbs, &rsa3072_key)
                    .unwrap()
                    .signature
            };
            writer.next().write_bitvec(&BitVec::from_bytes(&sig));
        });
    });

    // Base64 encode
    let x509_cert = base64::encode(&cert_der);

    // add PEM header and ending
    // let x509_cert_pem = format!(
    //     "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
    //     x509_cert
    // );
    // Ok(x509_cert_pem)

    Ok(x509_cert)
}

pub fn rsa_sign(message: String, iat: i64) -> SgxResult<sgx_rsa3072_signature_t> {
    let mut rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();
    // 5 minutes before the deadline still needs to update the key
    if (rsa_key_data.not_befer > iat as i64) | (rsa_key_data.not_after - ADVANCE_REFRESH_TIME < iat)
    {
        warn!("Rsa key not in time range. Generate new RSA key for access token");
        match update_rsa_key(RSA_KEY_PATH) {
            Ok(_) => rsa_key_data = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap(),
            Err(x) => {
                error!("update_rsa_key() failed for access token");
                return Err(x);
            }
        };
    }
    let rsa3072_key = sgx_rsa3072_key_t {
        modulus: rsa_key_data.modulus.clone().try_into().unwrap(),
        d: rsa_key_data.d.clone().try_into().unwrap(),
        e: rsa_key_data.e.clone().try_into().unwrap(),
    };

    let sign_value = rsgx_rsa3072_sign_slice(&message.as_bytes(), &rsa3072_key)?;
    Ok(sign_value)
}

pub fn init_rsa_key() -> SgxError {
    info!("Call init_rsa_key()");

    if read_rsa_key(RSA_KEY_PATH).is_err() {
        info!("Trying to generate a new RSA key.");
        update_rsa_key(RSA_KEY_PATH)?;
    };

    Ok(())
}

pub fn get_tee_jwk() -> SgxResult<String> {
    let x509_cert = match get_x509_cert() {
        Ok(x) => x,
        Err(x) => {
            error!("Get x509 cert failed");
            return Err(x);
        }
    };
    let rsa_sha256 = match get_base64url_rsa_data_sha256() {
        Ok(x) => x,
        Err(x) => {
            error!("Get sha256(rsa key) failed");
            return Err(x);
        }
    };
    let n = match get_base64url_n() {
        Ok(x) => x,
        Err(x) => {
            error!("Get modulus vlaue failed");
            return Err(x);
        }
    };
    let e = match get_base64url_e() {
        Ok(x) => x,
        Err(x) => {
            error!("Get e value failed");
            return Err(x);
        }
    };

    let tee_jwks_string = format!(
        r#"{{"kty":"RSA","use":"sig","n":"{}","e":"{}","kid":"{}","x5c":["{}"],"alg": "RS256"}}"#,
        n, e, rsa_sha256, x509_cert
    );

    debug!("{:?}", tee_jwks_string.clone());

    Ok(tee_jwks_string)
}


pub fn test_write_rsa_key() {
    let test_key: RSAKeyData = RSAKeyData {
        modulus: vec![1, 2, 3],
        d: vec![4, 5, 6],
        e: vec![7, 8, 9],
        p: vec![10, 11, 12],
        q: vec![13, 14, 15],
        dmp1: vec![16, 17, 18],
        dmq1: vec![19, 20, 21],
        iqmp: vec![22, 23, 24],
        not_befer: 0,
        not_after: 0,
    };

    {
        *RSA_KEY_DATA.lock().unwrap() = Some(test_key.clone());
        let res = write_rsa_key("test_file");
        assert_eq!(res.is_err(), false);
    }

    {
        let res = read_rsa_key("test_file");
        assert_eq!(res.is_err(), true);
    }

    remove_file("test_file").unwrap();
}

pub fn test_read_rsa_key() {
    {
        let res = read_rsa_key("test_file");
        assert_eq!(res.is_err(), true);
    }
    {
        SgxFile::create("test_file").unwrap();
        let res = read_rsa_key("test_file");
        assert_eq!(res.is_err(), true);
    }
    {
        let write_data: [u8; 16] = [0; 16];
        let mut file = SgxFile::create("test_file").unwrap();
        file.write(&write_data).unwrap();
        let res = read_rsa_key("test_file");
        assert_eq!(res.is_err(), true);
    }

    remove_file("test_file").unwrap();
}

pub fn test_update_rsa_key() {
    let res = update_rsa_key("test_file");
    assert_eq!(res.is_err(), false);

    let res = read_rsa_key("test_file");
    assert_eq!(res.is_err(), false);
}

pub fn test_get_base64url_rsa_data_sha256() {
    let test_key: RSAKeyData = RSAKeyData {
        modulus: vec![1, 2, 3],
        d: vec![4, 5, 6],
        e: vec![7, 8, 9],
        p: vec![10, 11, 12],
        q: vec![13, 14, 15],
        dmp1: vec![16, 17, 18],
        dmq1: vec![19, 20, 21],
        iqmp: vec![22, 23, 24],
        not_befer: 0,
        not_after: 0,
    };

    *RSA_KEY_DATA.lock().unwrap() = Some(test_key.clone());
    let sha = get_base64url_rsa_data_sha256().unwrap();
    assert_eq!(sha, "4M5MCu72NaLPkOBm7EV4RyftZw2hdsvTRDQpQQVnh6E=");
}

pub fn test_get_base64url_n() {
    let test_key: RSAKeyData = RSAKeyData {
        modulus: vec![1, 2, 3],
        d: vec![4, 5, 6],
        e: vec![7, 8, 9],
        p: vec![10, 11, 12],
        q: vec![13, 14, 15],
        dmp1: vec![16, 17, 18],
        dmq1: vec![19, 20, 21],
        iqmp: vec![22, 23, 24],
        not_befer: 0,
        not_after: 0,
    };

    *RSA_KEY_DATA.lock().unwrap() = Some(test_key.clone());
    let n = get_base64url_n().unwrap();
    assert_eq!(n, "AwIB");
}

pub fn test_get_base64url_e() {
    let test_key: RSAKeyData = RSAKeyData {
        modulus: vec![1, 2, 3],
        d: vec![4, 5, 6],
        e: vec![7, 8, 9],
        p: vec![10, 11, 12],
        q: vec![13, 14, 15],
        dmp1: vec![16, 17, 18],
        dmq1: vec![19, 20, 21],
        iqmp: vec![22, 23, 24],
        not_befer: 0,
        not_after: 0,
    };

    *RSA_KEY_DATA.lock().unwrap() = Some(test_key.clone());
    let e = get_base64url_e().unwrap();
    assert_eq!(e, "CQgH");
}

pub fn test_get_rsa_private_key_pem() {
    let test_key: RSAKeyData = RSAKeyData {
        modulus: vec![1, 2, 3],
        d: vec![4, 5, 6],
        e: vec![7, 8, 9],
        p: vec![10, 11, 12],
        q: vec![13, 14, 15],
        dmp1: vec![16, 17, 18],
        dmq1: vec![19, 20, 21],
        iqmp: vec![22, 23, 24],
        not_befer: 0,
        not_after: 0,
    };

    *RSA_KEY_DATA.lock().unwrap() = Some(test_key.clone());
    let pem = get_rsa_private_key_pem().unwrap();
    assert_eq!(pem, "-----BEGIN PRIVATE KEY-----\nMEECAQAwDQYJKoZIhvcNAQEBBQAELTArAgEAAgMDAgECAwkIBwIDBgUEAgMMCwoCAw8ODQIDEhEQAgMVFBMCAxgXFg==\n-----END PRIVATE KEY-----");
}

pub fn test_generate_quote() {
    update_rsa_key("test_file").unwrap();
    let res = generate_quote();
    assert_eq!(res.is_err(), false);

    remove_file("test_file").unwrap();
}

pub fn test_get_x509_cert() {
    update_rsa_key("test_file").unwrap();
    let res = get_x509_cert();
    assert_eq!(res.is_err(), false);

    remove_file("test_file").unwrap();
}

pub fn test_rsa_sign() {
    {
        let test_key: RSAKeyData = RSAKeyData {
            modulus: vec![
                87, 53, 146, 130, 222, 172, 121, 171, 62, 50, 178, 235, 52, 125, 116, 153, 60, 21,
                164, 234, 223, 114, 198, 203, 141, 149, 182, 25, 107, 24, 3, 226, 91, 19, 239, 136,
                202, 175, 59, 229, 226, 142, 192, 146, 197, 137, 37, 213, 26, 78, 241, 75, 96, 129,
                228, 30, 24, 104, 132, 20, 234, 45, 234, 130, 118, 140, 40, 136, 105, 57, 167, 175,
                25, 148, 8, 54, 247, 72, 156, 21, 210, 41, 153, 252, 157, 189, 178, 69, 108, 220,
                111, 131, 216, 4, 51, 54, 131, 204, 4, 5, 150, 125, 246, 43, 238, 15, 143, 230,
                187, 164, 213, 16, 142, 202, 8, 36, 161, 10, 197, 68, 22, 57, 101, 90, 134, 101,
                134, 236, 110, 16, 110, 135, 58, 184, 122, 47, 153, 102, 45, 176, 199, 243, 231,
                213, 74, 173, 81, 233, 107, 69, 226, 234, 165, 171, 235, 198, 199, 88, 133, 0, 158,
                75, 126, 30, 44, 241, 97, 68, 45, 97, 188, 226, 192, 44, 189, 112, 65, 152, 168,
                66, 175, 237, 1, 35, 193, 58, 242, 5, 98, 158, 91, 132, 58, 14, 23, 38, 153, 99,
                18, 67, 232, 133, 173, 46, 94, 154, 87, 254, 229, 16, 171, 29, 13, 218, 100, 74,
                176, 30, 30, 218, 185, 98, 205, 231, 26, 6, 158, 170, 2, 14, 56, 40, 68, 158, 34,
                246, 145, 212, 55, 171, 9, 132, 165, 131, 13, 64, 237, 178, 18, 254, 174, 149, 93,
                138, 102, 240, 25, 222, 180, 54, 245, 69, 182, 133, 168, 18, 136, 186, 109, 8, 195,
                214, 176, 86, 152, 113, 247, 137, 234, 95, 190, 133, 102, 225, 38, 214, 110, 128,
                211, 205, 129, 165, 124, 233, 118, 148, 244, 91, 161, 77, 75, 138, 30, 147, 191,
                153, 232, 230, 106, 31, 188, 92, 52, 76, 236, 244, 63, 144, 220, 141, 13, 135, 159,
                72, 253, 45, 36, 172, 219, 81, 232, 214, 227, 199, 76, 37, 210, 168, 97, 140, 82,
                68, 126, 20, 66, 150, 204, 140, 34, 203, 44, 88, 103, 127, 221, 109, 13, 194, 49,
                34, 24, 120, 105, 122, 92, 213, 200, 194, 222, 52, 124, 177, 94, 246, 219, 131,
                208, 98, 232, 31, 247, 231, 195, 162,
            ],
            d: vec![
                145, 221, 254, 211, 138, 207, 19, 119, 55, 162, 167, 41, 130, 104, 64, 159, 8, 154,
                82, 165, 48, 107, 203, 68, 46, 115, 29, 107, 71, 23, 154, 74, 216, 148, 8, 129, 19,
                9, 164, 65, 166, 36, 119, 145, 196, 242, 154, 196, 188, 201, 86, 89, 65, 128, 53,
                2, 238, 27, 240, 144, 159, 218, 180, 178, 0, 71, 100, 241, 29, 67, 45, 185, 104,
                117, 197, 177, 21, 247, 108, 28, 66, 32, 254, 56, 194, 175, 22, 203, 141, 91, 27,
                86, 8, 52, 72, 222, 87, 82, 239, 30, 75, 105, 167, 77, 243, 193, 34, 130, 7, 55,
                222, 70, 165, 152, 68, 3, 12, 168, 24, 188, 196, 236, 2, 214, 174, 68, 100, 44,
                159, 31, 152, 247, 25, 159, 103, 122, 232, 124, 105, 126, 113, 2, 139, 137, 235,
                192, 51, 56, 178, 32, 213, 63, 94, 0, 183, 156, 163, 242, 103, 36, 147, 0, 130,
                201, 115, 150, 156, 4, 229, 227, 109, 231, 131, 73, 184, 216, 111, 173, 213, 70,
                193, 157, 231, 17, 218, 210, 115, 41, 78, 142, 133, 59, 206, 82, 208, 87, 59, 36,
                154, 20, 79, 95, 214, 41, 157, 181, 70, 243, 59, 117, 201, 23, 186, 195, 24, 102,
                224, 237, 226, 162, 154, 126, 198, 37, 147, 61, 153, 243, 250, 213, 225, 238, 158,
                4, 226, 177, 228, 149, 141, 95, 11, 252, 84, 21, 104, 86, 119, 61, 254, 33, 203,
                157, 78, 83, 233, 143, 189, 68, 72, 215, 157, 190, 177, 27, 216, 5, 134, 141, 18,
                116, 12, 41, 207, 34, 6, 91, 60, 71, 47, 123, 59, 133, 158, 213, 171, 207, 43, 243,
                7, 47, 122, 12, 224, 114, 174, 122, 33, 4, 80, 112, 15, 36, 207, 109, 238, 55, 94,
                66, 166, 162, 136, 12, 61, 124, 193, 78, 18, 18, 37, 52, 211, 114, 124, 143, 102,
                184, 206, 70, 151, 114, 228, 66, 56, 161, 221, 114, 144, 59, 190, 255, 121, 46, 79,
                131, 227, 143, 199, 109, 199, 225, 183, 254, 229, 211, 202, 172, 202, 231, 143, 7,
                99, 132, 199, 226, 64, 27, 83, 114, 249, 233, 177, 171, 190, 206, 170, 36, 252,
                151, 46, 144, 62, 116, 90, 83,
            ],
            e: vec![1, 0, 1, 0],
            p: vec![
                101, 234, 115, 157, 91, 75, 208, 185, 64, 206, 35, 8, 176, 109, 2, 65, 128, 254,
                196, 10, 173, 183, 45, 224, 240, 86, 50, 94, 243, 48, 104, 105, 154, 243, 232, 64,
                41, 174, 110, 234, 23, 106, 63, 7, 227, 139, 195, 204, 148, 213, 206, 107, 242,
                135, 63, 85, 113, 155, 254, 247, 99, 190, 1, 76, 236, 117, 244, 255, 33, 94, 80,
                159, 249, 35, 247, 139, 8, 154, 9, 158, 47, 24, 199, 89, 154, 141, 193, 217, 170,
                137, 42, 8, 33, 125, 222, 167, 52, 196, 164, 51, 181, 136, 148, 81, 200, 70, 59,
                178, 33, 141, 204, 65, 68, 145, 198, 134, 174, 8, 156, 31, 93, 26, 130, 27, 193,
                25, 231, 46, 83, 49, 205, 2, 200, 19, 243, 192, 254, 25, 197, 255, 104, 249, 79, 5,
                43, 72, 2, 218, 18, 12, 71, 149, 254, 72, 179, 110, 222, 184, 55, 96, 107, 214,
                179, 209, 87, 77, 34, 33, 41, 208, 194, 10, 32, 54, 42, 216, 104, 138, 47, 17, 18,
                134, 49, 34, 241, 135, 130, 13, 109, 178, 198, 249,
            ],
            q: vec![
                11, 231, 94, 241, 250, 86, 88, 194, 85, 247, 188, 4, 161, 94, 3, 124, 252, 169,
                117, 122, 64, 39, 12, 110, 169, 238, 226, 213, 248, 215, 125, 184, 24, 125, 19, 53,
                157, 223, 14, 44, 129, 227, 13, 211, 178, 203, 179, 130, 144, 170, 224, 199, 255,
                204, 157, 114, 121, 205, 12, 21, 176, 102, 37, 136, 66, 236, 152, 98, 39, 64, 245,
                15, 166, 173, 89, 139, 30, 252, 185, 245, 41, 2, 0, 243, 123, 33, 109, 10, 127,
                110, 218, 152, 62, 178, 24, 59, 78, 185, 18, 112, 33, 229, 236, 111, 174, 132, 4,
                134, 26, 128, 64, 100, 183, 126, 150, 179, 18, 1, 172, 180, 83, 23, 168, 106, 127,
                239, 209, 77, 246, 142, 178, 229, 110, 206, 194, 175, 206, 59, 156, 62, 108, 29,
                192, 207, 11, 71, 3, 212, 4, 242, 154, 191, 241, 124, 90, 166, 190, 34, 176, 135,
                66, 252, 170, 158, 154, 204, 34, 76, 39, 8, 99, 149, 132, 170, 45, 179, 100, 31,
                20, 135, 202, 161, 174, 134, 136, 57, 178, 21, 90, 44, 210, 166,
            ],
            dmp1: vec![
                105, 234, 192, 115, 36, 253, 244, 199, 101, 152, 77, 200, 103, 64, 161, 117, 3, 26,
                120, 233, 214, 150, 106, 117, 116, 232, 84, 218, 64, 215, 213, 90, 44, 203, 194,
                45, 22, 169, 48, 169, 227, 29, 216, 208, 135, 160, 120, 227, 238, 18, 249, 145, 3,
                175, 113, 18, 204, 98, 227, 252, 182, 179, 213, 40, 1, 195, 150, 163, 250, 112, 89,
                63, 227, 56, 61, 192, 153, 112, 18, 165, 188, 4, 220, 237, 160, 120, 110, 58, 130,
                59, 100, 169, 92, 201, 62, 58, 25, 202, 0, 49, 211, 239, 63, 79, 240, 75, 47, 66,
                224, 246, 97, 70, 152, 99, 156, 82, 75, 77, 65, 110, 159, 207, 164, 108, 183, 172,
                123, 237, 50, 89, 11, 51, 102, 120, 108, 200, 181, 51, 247, 135, 181, 120, 238,
                220, 209, 163, 195, 163, 75, 147, 146, 95, 185, 200, 149, 165, 197, 164, 100, 168,
                85, 163, 212, 168, 45, 65, 210, 98, 222, 0, 217, 132, 211, 142, 65, 99, 127, 222,
                227, 32, 239, 236, 205, 206, 239, 39, 3, 225, 105, 227, 66, 56,
            ],
            dmq1: vec![
                87, 53, 189, 185, 24, 246, 223, 63, 201, 105, 99, 6, 100, 182, 74, 190, 95, 63, 44,
                192, 168, 93, 149, 209, 59, 20, 164, 193, 178, 110, 188, 31, 117, 35, 103, 213,
                138, 14, 84, 17, 161, 208, 154, 132, 205, 32, 136, 16, 173, 62, 98, 14, 31, 201,
                240, 246, 255, 203, 73, 238, 85, 92, 189, 68, 195, 175, 136, 32, 146, 176, 204, 11,
                114, 250, 181, 168, 214, 220, 3, 118, 23, 0, 90, 93, 192, 84, 94, 91, 213, 91, 82,
                73, 222, 182, 11, 237, 224, 79, 225, 21, 98, 14, 224, 151, 126, 94, 106, 168, 78,
                70, 174, 75, 51, 230, 202, 137, 203, 185, 0, 141, 253, 144, 161, 210, 71, 231, 100,
                123, 53, 137, 64, 84, 125, 180, 232, 18, 105, 215, 122, 10, 44, 180, 26, 102, 55,
                206, 162, 201, 133, 33, 210, 107, 235, 219, 177, 166, 194, 35, 171, 120, 189, 107,
                163, 27, 162, 3, 4, 17, 125, 115, 27, 112, 185, 109, 182, 137, 88, 135, 193, 32,
                127, 41, 22, 181, 119, 248, 126, 163, 248, 227, 42, 34,
            ],
            iqmp: vec![
                71, 243, 45, 99, 254, 227, 94, 7, 44, 185, 103, 55, 183, 79, 217, 36, 204, 164, 3,
                29, 80, 139, 23, 2, 71, 165, 224, 61, 93, 218, 118, 23, 139, 2, 24, 92, 240, 43,
                160, 109, 110, 59, 140, 110, 221, 230, 131, 249, 238, 124, 72, 123, 200, 66, 107,
                171, 232, 246, 209, 16, 41, 134, 138, 192, 143, 254, 234, 210, 134, 39, 236, 4,
                170, 204, 29, 156, 66, 200, 100, 13, 114, 8, 6, 141, 119, 60, 229, 224, 198, 81,
                113, 21, 178, 137, 12, 10, 128, 74, 162, 74, 124, 242, 73, 7, 214, 115, 32, 169,
                182, 157, 196, 225, 6, 173, 241, 38, 134, 211, 64, 39, 222, 9, 22, 109, 252, 84,
                225, 114, 69, 27, 184, 19, 15, 229, 32, 33, 21, 213, 186, 80, 42, 114, 234, 54, 10,
                194, 139, 226, 74, 99, 148, 241, 157, 62, 14, 237, 134, 79, 194, 218, 14, 195, 72,
                122, 71, 230, 42, 18, 127, 210, 226, 200, 124, 192, 130, 87, 36, 145, 154, 70, 162,
                82, 232, 44, 12, 45, 105, 1, 148, 236, 57, 109,
            ],
            not_befer: 1695643219,
            not_after: 1696248019,
        };
        *RSA_KEY_DATA.lock().unwrap() = Some(test_key.clone());
    }

    let rsa_key_data: RSAKeyData = (*RSA_KEY_DATA.lock().unwrap()).clone().unwrap();
    let iat = rsa_key_data.not_befer + 10 as i64;
    let message = "Hello!".to_string();
    let sign_message = rsa_sign(message, iat).unwrap().signature;
    let except_sign = [
        159, 29, 29, 236, 30, 234, 64, 239, 130, 19, 50, 194, 107, 9, 217, 0, 246, 35, 237, 210,
        29, 182, 93, 6, 44, 244, 211, 182, 210, 162, 84, 54, 16, 2, 226, 245, 218, 162, 75, 181,
        207, 212, 91, 102, 152, 23, 55, 186, 67, 205, 190, 199, 108, 133, 16, 21, 144, 178, 122,
        140, 171, 213, 92, 140, 0, 0, 10, 24, 102, 111, 185, 209, 8, 53, 176, 186, 182, 115, 129,
        213, 213, 169, 155, 254, 105, 140, 124, 8, 131, 198, 243, 250, 246, 41, 57, 254, 129, 231,
        64, 76, 146, 248, 43, 106, 237, 200, 36, 246, 83, 229, 168, 236, 19, 172, 117, 72, 217,
        219, 133, 230, 162, 178, 215, 92, 203, 129, 206, 216, 163, 66, 122, 198, 100, 176, 93, 121,
        220, 165, 18, 141, 149, 91, 164, 166, 34, 17, 191, 220, 201, 171, 60, 136, 231, 103, 102,
        51, 98, 151, 119, 162, 15, 232, 194, 71, 109, 108, 237, 153, 112, 15, 217, 225, 220, 33,
        45, 170, 23, 36, 65, 174, 174, 196, 217, 173, 70, 69, 167, 248, 31, 37, 244, 191, 32, 176,
        206, 159, 196, 212, 38, 140, 217, 62, 70, 115, 13, 151, 64, 237, 181, 208, 67, 244, 14, 62,
        110, 116, 35, 219, 210, 82, 226, 80, 46, 22, 6, 212, 211, 82, 244, 196, 135, 54, 104, 203,
        127, 1, 152, 91, 249, 56, 56, 192, 83, 15, 176, 117, 25, 109, 210, 6, 73, 54, 147, 213,
        119, 76, 241, 7, 132, 232, 49, 88, 25, 190, 73, 217, 153, 228, 8, 243, 233, 62, 200, 127,
        68, 221, 95, 155, 69, 122, 80, 22, 212, 34, 143, 219, 245, 221, 192, 132, 77, 228, 68, 193,
        160, 101, 145, 163, 211, 195, 217, 80, 179, 29, 207, 187, 136, 198, 239, 207, 129, 58, 237,
        101, 13, 189, 13, 148, 216, 10, 174, 32, 44, 117, 52, 133, 115, 48, 183, 32, 141, 53, 119,
        239, 35, 249, 141, 131, 137, 194, 212, 117, 239, 51, 156, 55, 117, 169, 67, 200, 3, 89,
        128, 20, 189, 65, 58, 162, 192, 249, 9, 30, 230, 47, 88, 83, 232, 58, 19, 204, 221, 169,
        33, 200, 162, 1, 180, 191, 78, 153, 74, 162, 125, 1,
    ];

    assert_eq!(sign_message, except_sign);
}