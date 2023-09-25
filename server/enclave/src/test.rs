use rsa::{
    test_generate_quote, test_get_base64url_e, test_get_base64url_n,
    test_get_base64url_rsa_data_sha256, test_get_rsa_private_key_pem, test_get_x509_cert,
    test_read_rsa_key, test_rsa_sign, test_update_rsa_key, test_write_rsa_key,
};
use auth::{
    test_update_jwks, test_update_config, test_get_access_token
};
use sgx_tunittest::*;
use std::string::String;
use std::vec::Vec;

pub fn test_all_function() {
    rsgx_unit_tests!(
        // rsa test
        test_write_rsa_key,
        test_read_rsa_key,
        test_update_rsa_key,
        test_get_base64url_rsa_data_sha256,
        test_get_base64url_n,
        test_get_base64url_e,
        test_get_rsa_private_key_pem,
        test_generate_quote,
        test_get_x509_cert,
        test_rsa_sign,

        // auth test
        test_update_jwks,
        test_update_config, 
        test_get_access_token,
    );
}
