#[macro_use]
extern crate lazy_static;
extern crate actix_web;
extern crate env_logger;
extern crate log;
extern crate openssl;
extern crate sgx_types;
use sgx_types::sgx_quote3_t;

use std::{sync::Mutex, collections::HashMap};

use actix_web::{client::{Client, Connector}, get, App, HttpServer, HttpRequest, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslConnector, SslVerifyMode};
use env_logger::Builder;
use log::{error, info, warn, LevelFilter, debug};
use serde::{Serialize, Deserialize};
use x509_parser::prelude::*;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

use intel_tee_quote_verification_rs::*;

const URL: &str = "https://127.0.0.1:8080/.well-known/jwks.json";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
struct Jwk {
    kty: String,
    n: String,
    e: String,
    kid: String,
    alg: String,

    #[serde(rename = "use")]
    public_key_use: String,

    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    x509_url: Option<String>,

    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    x509_chain: Option<Vec<String>>,

    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    x509_sha1_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default, Hash)]
struct JwkSet {
    keys: Vec<Jwk>,
}

lazy_static! {
    static ref JWK_INFO: Mutex<HashMap<String, (i64, Jwk)>> = Mutex::new(HashMap::new());
}

async fn update_jwks(url: &str) -> Result<(), String> {
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::NONE);

    let myconnector = builder.build();
    let client = Client::builder()
                            .connector(Connector::new().ssl(myconnector).finish()).finish();

    let mut response = client.get(url).send().await.unwrap();

    let body = response
        .body()
        .limit(10240)
        .await
        .unwrap().to_vec();
    let body_str = String::from_utf8_lossy(body.as_slice()).to_string();
    debug!("body_str: {}", body_str.clone());

    let jwk_set: JwkSet = serde_json::from_str(body_str.as_str()).unwrap();

    for jwk in jwk_set.keys {
        let n = jwk.n.clone();
        let e = jwk.e.clone();

        let x509_base64 = jwk.x509_chain.clone().unwrap();
        let x509 = base64::decode(x509_base64[0].as_bytes()).unwrap();

        let res = X509Certificate::from_der(x509.as_slice());
        match res {
            Ok((rem, cert)) => {
                assert!(rem.is_empty());
                
                let extensions = cert.tbs_certificate.extensions();
                let not_after = cert.tbs_certificate.validity.not_after.timestamp();
                let quote = extensions[0].value.to_vec();
                let p_quote3: *const sgx_quote3_t = quote.as_ptr() as *const sgx_quote3_t;
                let quote3: sgx_quote3_t = unsafe { *p_quote3 };

                debug!("quote: {:?}", quote);


                let p_collateral: Option<&[u8]> = None;
                let current_time = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap_or(std::time::Duration::ZERO)
                        .as_secs() as i64;
                let mut qve_report_info: sgx_ql_qe_report_info_t = Default::default();

                let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
                let mut supp_data_desc = tee_supp_data_descriptor_t {
                    major_version: 0,
                    data_size: 0,
                    p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
                };
                let p_supplemental_data = match supp_data_desc.data_size {
                    0 => None,
                    _ => Some(&mut supp_data_desc),
                };

                let res = tee_verify_quote(
                        quote.as_slice(),
                        p_collateral,
                        current_time,
                        Some(&mut qve_report_info),
                        p_supplemental_data);
                match res {
                    Ok((colla_exp_stat, qv_result)) => {
                        info!("collateral_expiration_status: {}, quote_verification_result: {:?}", colla_exp_stat, qv_result);
                        if colla_exp_stat != 0 || qv_result != sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK {
                            continue;
                        }

                        let report_date = quote3.report_body.report_data.d;

                        let public_key = format!("{{n: {}, e: {}}}", n, e);
                        debug!("public_key: {:?}", public_key);

                        let hash_public_key = sha256::digest(public_key.as_str());
                        let hash_public_key_bytes = hex::decode(hash_public_key).unwrap();

                        debug!("report_data: {:?}", report_date);
                        debug!("hash(public_key): {:?}", hash_public_key_bytes);
                        debug!("not_after: {}", not_after);
                        
                        if report_date[..32] == *hash_public_key_bytes.as_slice() {
                            let mut jwk_info = JWK_INFO.lock().unwrap();
                            jwk_info.insert(jwk.kid.clone(), (not_after, jwk));
                        } else {
                            warn!("jwk hash error: [{:?}]", jwk.clone());
                        }
                    }
                    Err(e) => warn!("tee_verify_quote failed: {:#04x}, error jwk: {:?}", e as u32, jwk.clone()),
                }
            },
            _ => panic!("x509 parsing failed: {:?}", res),
        }
    }

    let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs() as i64;

    let mut jwk_info = JWK_INFO.lock().unwrap();
    let mut key_remove: Vec<String> = Vec::new();
    for (jwk_not_after, jwk) in jwk_info.values() {
        if *jwk_not_after < now {
            key_remove.push(jwk.kid.clone());
        }
    }
    for key in key_remove {
        jwk_info.remove(&key);
    }

    Ok(())
}

#[get("/api")]
async fn api(req: HttpRequest) -> impl Responder {
    let mut token = "";

    if let Some(header_value) = req.headers().get("authorization") {
        let auth_header = header_value.to_str().unwrap();
        debug!("Authorization Header: {}", &auth_header[7..]);
        token = &auth_header[7..];
    }

    let header = match decode_header(token) {
        Ok(x) => x,
        Err(x) => {
            warn!("Access token header parsing failure. ERROR INFO: {:?}", x);
            return format!(r#"{{"msg": "Access token parsing failure"}}\n"#);
        }
    };
    let kid = match header.kid {
        Some(k) => k,
        None => {
            error!("Token doesn't have a `kid` header field");
            return format!(r#"{{"msg": "Access token kid parsing failure"}}\n"#);
        }
    };

    let jwk_info = JWK_INFO.lock().unwrap().clone();
    
    if jwk_info.get(&kid) == None {
        update_jwks(URL).await.unwrap();
    }

    let jwk_info = JWK_INFO.lock().unwrap().clone();
    if let Some((_, jwk)) = jwk_info.get(&kid) {
        let n = jwk.n.clone();
        let e = jwk.e.clone();

        let validation = Validation::new(Algorithm::RS256);

        let token_data = match decode::<HashMap<String, serde_json::Value>>(
            &token,
            &DecodingKey::from_rsa_components(n.as_str(), e.as_str()),
            &validation,
        ) {
            Ok(x) => x,
            Err(x) => {
                warn!("Access token decoding failed: {:?}", x);
                return format!(r#"{{"msg": "Access token decoding failed"}}\n"#);
            }
        };
    } else {
        warn!("Unable to parse the Access token");
        return "Unable to parse the Access token, may have provided the wrong Access token.".to_string();
    }

    r#"Access Token parsed successfully\n"#.to_string()
}

#[actix_web::main]
async fn main() {
    Builder::new().filter(None, LevelFilter::Info).init();

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();

    match HttpServer::new(|| {
            App::new()
                .service(api)
        })
        .bind_openssl("127.0.0.1:9999", builder).unwrap()
        .run()
        .await {
            Ok(_) => (),
            Err(x) => println!("{:?}", x),
        };
}