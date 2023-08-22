
use std::env;

fn main () {

    let sdk_dir = env::var("SGX_SDK")
                    .unwrap_or_else(|_| "/opt/sgxsdk".to_string());
    let is_sim = env::var("SGX_MODE")
                    .unwrap_or_else(|_| "HW".to_string());

    println!("cargo:rustc-link-search=native=../lib");
    println!("cargo:rustc-link-lib=static=Enclave_u");

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=static=sgx_uprotected_fs");
    println!("cargo:rustc-link-lib=dylib=sgx_dcap_ql");
    println!("cargo:rustc-link-lib=dylib=sgx_dcap_quoteverify");
    
    match is_sim.as_ref() {
        "SW" => println!("cargo:rustc-link-lib=dylib=sgx_urts_sim"),
        "HW" => {
            println!("cargo:rustc-link-lib=dylib=sgx_urts");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
            // println!("cargo:rustc-link-lib=dylib=libdcap_quoteprov.so");
        },
        _    => println!("cargo:rustc-link-lib=dylib=sgx_urts"), // Treat undefined as HW
    }
}