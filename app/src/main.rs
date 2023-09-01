extern crate sgx_types;
extern crate sgx_urts;
extern crate log;
extern crate env_logger;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use log::{info, warn, error, LevelFilter};
use env_logger::Builder;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern {
    fn run_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    info!("Call init_enclave()");
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

#[no_mangle]
pub extern "C" fn ocall_get_target_info(
    ti: *mut sgx_target_info_t
) -> sgx_status_t {
    let result = unsafe {
        sgx_qe_get_target_info(ti)
    };
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
    p_report           : *mut sgx_report_t,
    p_quote            : *mut u8,
    max_quote_len      : u32,
    p_quote_len        : *mut u32
) -> sgx_status_t {
    let mut quote_size: u32 = 0;

    let qe3_ret = unsafe { sgx_qe_get_quote_size(&mut quote_size as _) };
    if qe3_ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
        error!("Error in sgx_qe_get_quote_size(), error code: {:?}", qe3_ret);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    if quote_size > max_quote_len {
        error!("The quote size({:?}) exceeds the maximum value {:?}", quote_size, max_quote_len);
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

fn main() {
    Builder::new()
        .filter(None, LevelFilter::Info)
        .init();

    let enclave = match init_enclave() {
        Ok(r) => {
            info!("Init Enclave Successful! Enclave id: {}", r.geteid());
            r
        },
        Err(x) => {
            error!("Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        run_server(enclave.geteid(), &mut retval)
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            error!("ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    enclave.destroy();
}