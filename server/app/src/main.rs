extern crate actix_web;
extern crate env_logger;
extern crate log;
extern crate openssl;
extern crate sgx_types;
extern crate sgx_urts;
#[macro_use]
extern crate lazy_static;

use actix_web::{get, web, App, HttpRequest, HttpServer, Responder};
use env_logger::Builder;
use log::{error, info, warn, LevelFilter};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::sync::Mutex;
use std::{fs, str};

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

lazy_static! {
    static ref ENCLAVE_ID: Mutex<u64> = Mutex::new(0);
}

extern "C" {
    fn init_tee(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    fn get_tee_jwks(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        tee_jwks: *mut u8,
        max_jwks_len: usize,
        tee_jwks_len: *mut usize,
    ) -> sgx_status_t;

    fn get_access_token(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        id_token: *const u8,
        id_token_len: usize,
        access_token: *mut u8,
        max_token_len: usize,
        access_token_len: *mut usize,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    info!("Call init_enclave()");
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

#[no_mangle]
pub extern "C" fn ocall_get_target_info(ti: *mut sgx_target_info_t) -> sgx_status_t {
    let result = unsafe { sgx_qe_get_target_info(ti) };
    match result {
        sgx_quote3_error_t::SGX_QL_SUCCESS => return sgx_status_t::SGX_SUCCESS,
        other => {
            error!("Error in ocall_get_target_info(): {:?}", other);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }
}

#[no_mangle]
pub extern "C" fn ocall_generate_quote(
    p_report: *mut sgx_report_t,
    p_quote: *mut u8,
    max_quote_len: u32,
    p_quote_len: *mut u32,
) -> sgx_status_t {
    let mut quote_size: u32 = 0;

    let qe3_ret = unsafe { sgx_qe_get_quote_size(&mut quote_size as _) };
    if qe3_ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
        error!(
            "Error in sgx_qe_get_quote_size(), error code: {:?}",
            qe3_ret
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    if quote_size > max_quote_len {
        error!(
            "The quote size({:?}) exceeds the maximum value {:?}",
            quote_size, max_quote_len
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let mut quote_vec: Vec<u8> = vec![0; quote_size as usize];

    let qe3_ret =
        unsafe { sgx_qe_get_quote(p_report as _, quote_size, quote_vec.as_mut_ptr() as _) };

    if qe3_ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
        error!("Error in sgx_qe_get_quote(), error code: {:?}", qe3_ret);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    unsafe {
        let quote_ptr = quote_vec.as_ptr();
        let quote_len = quote_vec.len();

        *p_quote_len = quote_len as u32;
        std::ptr::copy_nonoverlapping(quote_ptr, p_quote, quote_len);
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ocall_read_file(
    path: *mut u8,
    path_len: usize,
    file_content: *mut u8,
    max_content_len: usize,
    content_len: *mut usize,
) -> sgx_status_t {
    let path_slice = unsafe { std::slice::from_raw_parts_mut(path, path_len) };
    let path_string = String::from_utf8(path_slice.to_vec()).unwrap();

    let data = match fs::read(path_string) {
        Ok(x) => x,
        Err(x) => {
            warn!("read file failed: {:?}", x);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    if data.len() > max_content_len {
        warn!(
            "config file content length over limit, actual length: {} limit max length:{}",
            data.len(),
            max_content_len
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let raw_buf = unsafe {
        *content_len = data.len() as usize;
        std::slice::from_raw_parts_mut(file_content as *mut u8, data.len() as usize)
    };
    raw_buf.copy_from_slice(data.as_slice());

    sgx_status_t::SGX_SUCCESS
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenBody {
    id_token: String,
}

const MAX_ACCESS_TOKEN_LEN: usize = 9999;
const MAX_JWKS_LEN: usize = 9999;

#[get("/stsToken")]
async fn sts_token(_req: HttpRequest, body: web::Json<IdTokenBody>) -> impl Responder {
    let request_body = body.into_inner();
    let id_token = request_body.id_token.clone();

    let enclave_id = *ENCLAVE_ID.lock().unwrap();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut access_token_buf = vec![0; MAX_ACCESS_TOKEN_LEN];
    let mut access_token_len = 0;

    let result = unsafe {
        get_access_token(
            enclave_id as sgx_enclave_id_t,
            &mut retval,
            id_token.as_ptr() as *const u8,
            id_token.len(),
            access_token_buf.as_mut_ptr(),
            MAX_ACCESS_TOKEN_LEN,
            &mut access_token_len,
        )
    };

    let res = match result {
        sgx_status_t::SGX_SUCCESS => match retval {
            sgx_status_t::SGX_SUCCESS => {
                String::from_utf8(access_token_buf[..access_token_len].to_vec()).unwrap()
            }
            _ => return "{{\"msg\": \"Get access token failed\"}}\n".to_string(),
        },
        other => {
            error!("ECALL Enclave Failed {:?}!", other);
            return "Get access token failed\n".to_string();
        }
    };
    info!("Generating access token");

    format!("{{\"Access Token\": \"{}\"}}\n", res)
}

#[get("/.well-known/jwks.json")]
async fn jwks(_req: HttpRequest) -> impl Responder {
    let enclave_id = *ENCLAVE_ID.lock().unwrap();
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let mut tee_jwks_buf = vec![0; MAX_JWKS_LEN];
    let mut tee_jwks_len = 0;

    let res = match unsafe {
        get_tee_jwks(
            enclave_id as sgx_enclave_id_t,
            &mut retval,
            tee_jwks_buf.as_mut_ptr(),
            MAX_JWKS_LEN,
            &mut tee_jwks_len,
        )
    } {
        sgx_status_t::SGX_SUCCESS => match retval {
            sgx_status_t::SGX_SUCCESS => {
                String::from_utf8(tee_jwks_buf[..tee_jwks_len].to_vec()).unwrap()
            }
            _ => return "{{\"msg\": \"Get jwks failed\"}}\n".to_string(),
        },
        other => {
            error!("ECALL Enclave Failed {:?}!", other);
            return "Get jwks failed".to_string();
        }
    };
    info!("Generating jwks");

    format!("{{\"Jwks\": \"{}\"}}\n", res)
}

#[actix_web::main]
async fn main() {
    Builder::new().filter(None, LevelFilter::Info).init();

    let enclave = match init_enclave() {
        Ok(r) => {
            info!("Init Enclave Successful! Enclave id: {}", r.geteid());
            r
        }
        Err(x) => {
            error!("Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    {
        let mut enclave_id = ENCLAVE_ID.lock().unwrap();
        *enclave_id = enclave.geteid();
    }

    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { init_tee(enclave.geteid(), &mut retval) };

    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            error!("ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();

    match HttpServer::new(|| {
            App::new()
                .service(sts_token)
                .service(jwks)
        })
        .bind_openssl("127.0.0.1:8080", builder).unwrap()
        .run()
        .await {
            Ok(_) => (),
            Err(x) => println!("{:?}", x),
        };

    enclave.destroy();
}
