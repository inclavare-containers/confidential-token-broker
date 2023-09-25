use std::collections::HashMap;
use std::prelude::v1::*;

use http_req::{request::RequestBuilder, tls, uri::Uri};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use rsa::{get_base64url_rsa_data_sha256, rsa_sign};
use sgx_tcrypto::*;
use sgx_types::*;
use std::convert::TryInto;
use std::net::TcpStream;
use std::str;
use std::string::String;
use std::sync::SgxMutex;
use std::time::SystemTime;
use std::vec::Vec;

pub const CONFIG_PATH: &str = "CONFIG";
const MAX_CONFIG_LEN: usize = 9999;

extern "C" {
    pub fn ocall_read_file(
        ret_val: *mut sgx_status_t,
        path: *const u8,
        path_len: usize,
        file_content: *mut u8,
        max_content_len: usize,
        content_len: *mut usize,
    ) -> sgx_status_t;
}

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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Role {
    idp: String,
    jwk_endpoint: String,
    client_id: String,
    server_api: Vec<String>,
    scope: String,
    expiration: i64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct ConfigSet {
    configs: Vec<Role>,
}

impl ConfigSet {
    fn find(&self, idp: &str, client_id: &str) -> Option<&Role> {
        self.configs
            .iter()
            .find(|role| role.idp.as_str() == idp && role.client_id.as_str() == client_id)
    }

    fn jwk_endpoints(&self) -> Vec<String> {
        let mut jwk_endpoints: Vec<String> = Vec::new();
        for role in self.configs.iter() {
            jwk_endpoints.push(role.jwk_endpoint.clone());
        }
        jwk_endpoints
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    aud: Vec<String>,
    sub: String,
    iat: i64,
    exp: i64,
    scope: String,
    client_id: String,
}

lazy_static! {
    static ref JWKS: SgxMutex<HashMap<String, Jwk>> = SgxMutex::new(HashMap::new());
}

lazy_static! {
    static ref CONFIG: SgxMutex<Option<ConfigSet>> = SgxMutex::new(None);
}

pub fn update_jwks(jwk_endpoints: Vec<String>) -> SgxError {
    info!("Call update_jwks()");
    for endpoint in &jwk_endpoints {
        //Parse uri and assign it to variable `addr`
        let addr: Uri = endpoint.parse().unwrap();
        let mut conn_addr: Option<String> = None;

        if addr.port() != None {
            conn_addr = Some(format!("{}:{}", addr.host().unwrap(), addr.port().unwrap()));
        } else {
            if addr.scheme() == "https" {
                conn_addr = Some(format!("{}:{}", addr.host().unwrap(), "443"));
            } else if addr.scheme() == "http" {
                conn_addr = Some(format!("{}:{}", addr.host().unwrap(), "80"));
            }
        }
        //Connect to remote host
        let stream = TcpStream::connect(conn_addr.unwrap()).unwrap();

        //Open secure connection over TlsStream, because of `addr` (https)
        let mut stream = tls::Config::default()
            .connect(addr.host().unwrap_or(""), stream)
            .unwrap();

        //Container for response's body
        let mut writer = Vec::new();

        //Add header `Connection: Close`
        RequestBuilder::new(&addr)
            .header("Connection", "Close")
            .send(&mut stream, &mut writer)
            .unwrap();

        let text: String = String::from_utf8(writer).unwrap();
        let jwks: JwkSet = serde_json::from_str(text.as_str()).unwrap();
        let mut jwks_map = JWKS.lock().unwrap();
        for jwk in &jwks.keys {
            if !jwks_map.contains_key(&jwk.kid) {
                jwks_map.insert(jwk.kid.clone(), jwk.clone());
            }
        }
    }
    Ok(())
}

pub fn update_config(path: &str) -> SgxError {
    info!("Call update_config()");

    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut content_buf: [u8; MAX_CONFIG_LEN] = [0; MAX_CONFIG_LEN];
    let mut content_len: usize = 0;

    if unsafe {
        ocall_read_file(
            &mut rt as *mut sgx_status_t,
            path.as_ptr(),
            path.len() as usize,
            content_buf.as_mut_ptr(),
            MAX_CONFIG_LEN,
            &mut content_len,
        )
    } != sgx_status_t::SGX_SUCCESS
    {
        error!("OCALL Failed!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let aes_key: [u8; 16] = [0_u8; 16];
    let mut iv: [u8; 16] = [0_u8; 16];
    let mut plaintext_vec: Vec<u8> = vec![0; content_len];
    let plaintext_slice = &mut plaintext_vec[..];
    rsgx_aes_ctr_decrypt(
        &aes_key,
        &content_buf[..content_len],
        &mut iv,
        128,
        plaintext_slice,
    )?;

    let decrypt_config = String::from_utf8(plaintext_vec).unwrap();

    let new_config: ConfigSet = match serde_json::from_str(decrypt_config.as_str()) {
        Ok(x) => x,
        Err(x) => {
            warn!("Decode config file failed. ERROR CODE: {:?}", x);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };
    
    {
        let mut config = CONFIG.lock().unwrap();
        *config = Some(new_config.clone());
    }
    Ok(())
}

pub fn get_access_token(id_token: String) -> SgxResult<String> {
    info!("Call get_access_token()");

    let header = match decode_header(id_token.as_str()) {
        Ok(x) => x,
        Err(x) => {
            warn!("id token header parsing failure. ERROR INFO: {:?}", x);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };
    let kid = match header.kid {
        Some(k) => k,
        None => {
            error!("Token doesn't have a `kid` header field");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };
    let now = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap()
    .as_secs()
    .try_into()
    .unwrap();

    // Hourly update of configuration rules
    if now % 3600 == 0 {
        match update_config(CONFIG_PATH) {
            Ok(()) => (),
            Err(x) => {
                error!("update config failed");
                return Err(x);
            }
        }
    }

    let config: ConfigSet = (*CONFIG.lock().unwrap()).clone().unwrap();

    let mut jwks = JWKS.lock().unwrap().clone();
    let jwk = match jwks.get(&kid) {
        Some(x) => x,
        None => {
            update_jwks(config.jwk_endpoints())?;
            jwks = JWKS.lock().unwrap().clone();
            match jwks.get(&kid) {
                Some(x) => x,
                None => {
                    warn!("Could not find the public key to authenticate jwt");
                    return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
                }
            }
        }
    };

    let validation = Validation::new(Algorithm::RS256);

    let token_data = match decode::<HashMap<String, serde_json::Value>>(
        &id_token,
        &DecodingKey::from_rsa_components(jwk.n.as_str(), jwk.e.as_str()),
        &validation,
    ) {
        Ok(x) => x,
        Err(x) => {
            warn!("id token decoding failed: {:?}", x);
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    let result = config.find(
        token_data.claims["iss"].as_str().unwrap(),
        token_data.claims["aud"].as_str().unwrap(),
    );
    let role = match result {
        Some(x) => x,
        None => {
            warn!("id token information does not match configuration information");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };

    let iss = "enclave authorization".to_string();
    let aud = role.server_api.clone();
    let sub = token_data.claims["sub"].as_str().unwrap().to_string();
    let iat: i64 = now;
    let exp: i64 = iat + role.expiration;
    let scope = role.scope.clone();
    let client_id = role.client_id.clone();

    let mut access_header = Header::new(Algorithm::RS256);
    access_header.typ = Some("JWT".to_string());
    access_header.kid = Some(get_base64url_rsa_data_sha256().unwrap());

    let access_claims = AccessTokenClaims {
        iss,
        aud,
        sub,
        iat,
        exp,
        scope,
        client_id,
    };
    let encode_header = base64::encode_config(
        serde_json::to_vec(&access_header).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );
    let encode_claims = base64::encode_config(
        serde_json::to_vec(&access_claims).unwrap(),
        base64::URL_SAFE_NO_PAD,
    );
    let message = [encode_header, encode_claims].join(".");

    let signature = base64::encode_config(
        rsa_sign(message.clone(), iat).unwrap().signature,
        base64::URL_SAFE_NO_PAD,
    );
    let access_token = [message, signature].join(".");
    info!("access token: {:?}", &access_token);

    Ok(access_token)
}




pub fn test_update_jwks() {
    let res = update_jwks(vec!["https://dev-f3qm0elg4mvfgpsu.us.auth0.com/.well-known/jwks.json".to_string()]);
    assert_eq!(res.is_err(), false);
}

pub fn test_update_config() {
    {
        let res = update_config("test_file");
        assert_eq!(res.is_err(), true);
    }
    
    {
        let res = update_config(CONFIG_PATH);
        assert_eq!(res.is_err(), false);
    }
}

pub fn test_get_access_token() {
    {
        let id_token = "sadfjsald".to_string();
        let res = get_access_token(id_token);
        assert_eq!(res.is_err(), true);
    }

    {
        let id_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJ4TTBENGRFTHNZeTk5bm1qYU5zNSJ9.eyJpc3MiOiJodHRwczovL2Rldi1mM3FtMGVsZzRtdmZncHN1LnVzLmF1dGgwLmNvbS8iLCJhdWQiOiJJTUlwcmRQNHFmU3VLQU5ldldrSnloRzVGN3dlRUdUMCIsImlhdCI6MTY5NTMxNjcxMCwiZXhwIjoxNjk1MzUyNzEwLCJzdWIiOiJnb29nbGUtb2F1dGgyfDEwNzE4NjMyMzY5MDgyNjEzMzc0NiIsInNpZCI6Inp0ODVrNGtxWnRqT2VKU1lRU25VcURfUjFZeHRpNUxDIn0.aGeLnG2IbJ_kAUYNihb8nRrev2r-zu-NQQCqlUQOvh8NZ1hz8GTb_nf0vipCWSfdm3IVqYtFJwx6kol3SkCIS-H3efzAZNUh99Rvs_TkVaJEikOv6XRkPpdhRZMg0d6knFek4XmqiWSKHPixMcFnGlAOTGWo_0PvL1kkc-nZBBg3wuTfOcAZj4ylwQRaNBbjy7mSG7Ci5GOr5Dw-abYNTJQuKvTGZuHkArJxdVdHj5AVNpXN57Y9V0Os1gDfUsaohhpaRSd-LDKPY0O5Bb-3RSHQLveeA95f90V2sWGMm5KZpgszVWHQmhC8Co2Ae1jRhTEgvU_yKYiLpLU1fP5cXw".to_string();
        let res = get_access_token(id_token);
        assert_eq!(res.is_err(), true);
    }
}
