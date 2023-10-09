# confidential-token-broker

[![License](https://img.shields.io/badge/license-Apache-green.svg)](LICENSE)[![Homepage](https://img.shields.io/badge/site-homepage-blue)](https://github.com/inclavare-containers/confidential-token-broker)

<p align="center"><a href="./README.md">English</a>|<a href="./README.zh_CN.md">简体中文</a></p>

This project is based on the hardware-level protection provided by the Trusted Execution Environment (TEE) to realize secure and reliable resource privilege issuance and authentication. The project solves the problem of cross-domain resource authentication with the help of JWT(JSON Web Token) format tokens. At the same time, to ensure the security of authentication, the issuance of JWT tokens is placed in the TEE. To ensure the safety of token verification, the remote proof capability provided by intel sgx is utilized to protect the public key corresponding to the RSA key used for issuance. The project mainly contains the following technical solutions:

- Resource authorization and privilege verification based on OIDC's specifications and processes
- Completing the issuance of authorization tokens in the TEE to ensure the security of the token issuance process.
- Protect the trustworthiness of the public key corresponding to the private key used for issuing tokens with the help of Intel sgx remote attestation capability.
- Convert Idp's id token into an access token and issue it to the resource requesting user according to the configuration rules.

![OSPP-Sequence Diagram](./img/OSPP-Sequence%20Diagram.svg)

## Prerequisites

### Supported HW

First of all, please make sure your hardware is supporting [Intel SGX](https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html) and [FLC]( https://www.intel.com/content/www/us/en/developer/articles/technical/an-update-on-3rd-party-attestation.html)(Flexible Launch Control). It may be necessary for some supported hardware to enable the relevant features in the BIOS.

You can use the command `cpuid` to see if the hardware platform meets the requirements.

- SGX2：`cpuid | grep SGX`
- FLC：`cpuid | grep SGX_LC`

### Building an SGX Confidential Computing Environment

- [Intel sgx sdk install guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)
- [DCAP Quick Install Guide](https://software.intel.com/content/www/us/en/develop/articles/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html)

### Configure a valid PCCS service

This project uses the [PCCS](https://download.01.org/intel-sgx/sgx-dcap/1.10/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf) service provided by Aliyun. If you are using a non-Aliyun server, `https://sgx-dcap-server.cn-shanghai.aliyuncs.com/sgx/certification/v3/` is a valid PCCS URL, you need to update the `/etc/sgx_default_qcnl.conf` file with the valid PCCS URL.

Suppose you are using a confidential computing server provided by Aliyun. In that case, you can refer to the official [documentation](https://help.aliyun.com/zh/ecs/user-guide/build-an-sgx-encrypted-computing-environment) provided by Aliyun to build a confidential computing environment and configure the remote attestation service.

### Install rust

- Rust nightly-2022-10-22

### Configure Idp service and token conversion rules

This project uses [auth0](https://auth0.com/) as Idp by default, and token conversion is performed according to the configuration file. The configuration file is encrypted by AES CTR mode, and the server-side program will read the `CONFIG` file when initializing and decrypt and read the configuration set by the administrator for token conversion.

The default configuration file has the following plaintext format.

```json
{
	"configs": [
		{
			"idp": "https://dev-f3qm0elg4mvfgpsu.us.auth0.com/",
			"jwk_endpoint": "https://dev-f3qm0elg4mvfgpsu.us.auth0.com/.well-known/jwks.json",
			"client_id": "IMIprdP4qfSuKANevWkJyhG5F7weEGT0",
			"server_api": [
				"https://example.com/server1-api",
				"https://example.com/server2-api"
			],
			"scope": "openid profile read:admin",
			"expiration": 3600
		}
	]
}
```

The default profile decryption settings in the code are as follows

```rust
# server/enclave/src/auth.rs

let aes_key: [u8; 16] = [0_u8; 16]; // 178 line
let mut iv: [u8; 16] = [0_u8; 16]; // 179 line
```

Configure the decryption key and configure the rule file according to your needs before running the project (Note: the content of the rule file is the encrypted rules)

## Project compile and run

The server described below refers to the authorization center of the token, and the client relates to the verification center of the token.

### Server-side compilation

```shell
cd server
make
```

### server-side running

```
cd bin
./app
```

- The server receives the id token in the following format at `https://127.0.0.1:8080/stsToken` and returns the access token

  ```json
  {"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJ4TTBENGRFTHNZeTk5bm1qYU5zNSJ9.eyJpc3MiOiJodHRwczovL2Rldi1mM3FtMGVsZzRtdmZncHN1LnVzLmF1dGgwLmNvbS8iLCJhdWQiOiJJTUlwcmRQNHFmU3VLQU5ldldrSnloRzVGN3dlRUdUMCIsImlhdCI6MTY5NTg5MDc3NiwiZXhwIjoxNjk1OTI2Nzc2LCJzdWIiOiJnb29nbGUtb2F1dGgyfDEwNzE4NjMyMzY5MDgyNjEzMzc0NiIsInNpZCI6IjdXTzM3YVd1UUVNU1F6QkZUc0hQUU1la0FQYmFuOHJJIn0.tmOMqJtSaQ6-AW8LnWyQUA36zmcvQF2IT9BvO0s2ExltUOBZ_T-51vSWh3_KBy21khFWVVr0T6QxldaTC-JFgzdP7zZwSYp7qUPMDSBVfuTnGRtRtVhinFgtcxcoB12DQ3JX3ZeLxtVkN_566Oh282UYxuVsQxJsG_brIJKU186K52Unq0eeabUOWJq8nZqulpbjGhSI6tEqlgWd0TJIvRgxUrwfef3fDfSnlN9cKiQ3RlfVy9bgyKPjEGlB0C8Ch4HO76t5w72AHIMMdsxrluSI5sgilFqYtEz4dVwxVKeg_tKtFwzG4Ut7UmjDl1kgryTZNSo--do0s3qyb-TRTQ"}
  ```

  - Request example

  ```shell
  curl -k -X GET "https://127.0.0.1:8080/stsToken" -H "Content-Type: application/json" -d '{"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJ4TTBENGRFTHNZeTk5bm1qYU5zNSJ9.eyJpc3MiOiJodHRwczovL2Rldi1mM3FtMGVsZzRtdmZncHN1LnVzLmF1dGgwLmNvbS8iLCJhdWQiOiJJTUlwcmRQNHFmU3VLQU5ldldrSnloRzVGN3dlRUdUMCIsImlhdCI6MTY5NjA1MjQyMywiZXhwIjoxNjk2MDg4NDIzLCJzdWIiOiJnb29nbGUtb2F1dGgyfDEwNzE4NjMyMzY5MDgyNjEzMzc0NiIsInNpZCI6IjdXTzM3YVd1UUVNU1F6QkZUc0hQUU1la0FQYmFuOHJJIn0.NclELlaI8tOa_gYZGxCbG_JDRpQypLk-kdrX3fBMFAkhCaBtrd4vyLXaCod8eRQ-QyoOC9BaAe5pMXAM2GEw3m178AYeL1dU2CDZmzkMsZo157j8Om_yixOMI22sGgkT-tfoDoEsfhjZeRVhXMe1SwnMYWqbBzEQ8crsEpx4xfx798jv_FjsoLz1fxTY-7nhxe9wu360aIjIQKwF_dT7wscklyRbp_7o0Rp3XNiOYhGem-CKfVY2aw-qry2gNmfzJ1nc1bV6SRf60y2n6GPsAoqCgaLTodGP4PjLoBNSZoMC9VFOiRp1lPSIwzIy36X3xkSNqHqS91xMvCC-uBrjOA"}'
  ```

  - Request Response Example

  ```json
  {"Access Token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9vVStqNDNPSFZBNTQwcGZsZXBoamVja29kL044Zy8yWnZtS1ROVm5JcU09In0.eyJpc3MiOiJlbmNsYXZlIGF1dGhvcml6YXRpb24iLCJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbS9zZXJ2ZXIxLWFwaSIsImh0dHBzOi8vZXhhbXBsZS5jb20vc2VydmVyMi1hcGkiXSwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMDcxODYzMjM2OTA4MjYxMzM3NDYiLCJpYXQiOjE2OTYwNTM5MDYsImV4cCI6MTY5NjA1NzUwNiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOmFkbWluIiwiY2xpZW50X2lkIjoiSU1JcHJkUDRxZlN1S0FOZXZXa0p5aEc1Rjd3ZUVHVDAifQ.Kf1lFg0IuOPEgZ7NFZ8lFOcjlwgXX5ys0apRFMUNXCqR6SbeoqORK5IIBMBmkNBYxuiozrzz4b6sUKj3_VBLhiZV3Yh9eUra_Wym21PFB8_hUaZuFbFHwS-RqnE5qhSSCdkiHwD55LQuiq7-sPtgbgMRBovHLJIa185GAxAwC7zqVEe8kGbnCI2hhGvfajuHYR3U_GOq5LhqhIa5ub_k55Z8cCwPghzfRRolsgcF6NsSRDiqxxe4S6J6-34jXBTyiDrLoKBDQRVlRp6LhttfYfcS_TCIoi4zafrA2UqJhzzFmp2UsBMC7ws0dqHfARAKDpT4AVf_5Nk1Y6-OZvOmhsu6_obeaf-1aM4G_Cx11Yv4-_3zbLgKwFB2V4U4AQ-VlIlAj2lB1SV5SIP9l6h6jdBfsg7MWrNJy85-2zJ0DxDyma8kuUxeMDynJVOovfehZ2c23aNw0OaZXqG36UrhTP2t2Mu3RwaTJvaPrUB3VRjctxTo_VlY6RL9I6OC5GZe"}
  ```

- The server will provide access to the [jwks](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key- sets)

  - Request example

  ```shell
  curl -k -X GET "https://127.0.0.1:8080/.well-known/jwks.json"
  ```

  - Request Response Example

  ```json
  {"keys":[{"kty":"RSA","use":"sig","n":"hcSsltyT2VTXUWWTyypStEV5xfYLYUAlm7qs6xN1HsEbB5Cy-z0QuCM6vzjmZw5IlyYXXh2fHkXWqGpP8yjeBSXdyEs0r49XD_5VnzscCkxe6XkczknAjdzv3A3tsZfypjLt5kFOh1FwZBwWRWYv3eiy5gNMK8EgkfFwtWmmATC2c37KTkJYqpTtOVboTHfqc0lxBdq-HFO3wmXzRqrsczjTMT6HsAzodK8bt5ipQrrtrp_T-EUFis1FoSUbnV7uaxdZQFh6KupbZ8trvyvol0frDy7pSzSruvNBztDAZ93Q6Js2zBFjEPyfcpBv61eHzxnh5t1hmrr7jDFnJgDM2kUkBhNYarJ1DMTVVKDuaBO6XUfrYPPPgJPfDXTZB-LhFXO_lQ6J3XBAeMjUXvJ--0s9h9XvLDpCn-N6SLSeIFs71X7xNhJ77tFPAN34fCwhrqiI3--oW9WS2JmxbihnT9dD3_dO1AKFpymNNBojm_9u4wMhquRWVmZkzqceU5nH","e":"AQAB","kid":"OoU+j43OHVA540pflephjeckod/N8g/2ZvmKTNVnIqM=","x5c":["MIIWVjCCFMCgAwIBAgIBATALBgkqhkiG9w0BAQswJDEiMCAGA1UEAwwZY29uZmlkZW50aWFsLXRva2VuLWJyb2tlcjAeFw0yMzA5MjYwNzE1NThaFw0yMzEwMDMwNzE1NThaMCQxIjAgBgNVBAMMGWNvbmZpZGVudGlhbC10b2tlbi1icm9rZXIwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCFxKyW3JPZVNdRZZPLKlK0RXnF9gthQCWbuqzrE3UewRsHkLL7PRC4Izq/OOZnDkiXJhdeHZ8eRdaoak/zKN4FJd3ISzSvj1cP/lWfOxwKTF7peRzOScCN3O/cDe2xl/KmMu3mQU6HUXBkHBZFZi/d6LLmA0wrwSCR8XC1aaYBMLZzfspOQliqlO05VuhMd+pzSXEF2r4cU7fCZfNGquxzONMxPoewDOh0rxu3mKlCuu2un9P4RQWKzUWhJRudXu5rF1lAWHoq6ltny2u/K+iXR+sPLulLNKu680HO0MBn3dDomzbMEWMQ/J9ykG/rV4fPGeHm3WGauvuMMWcmAMzaRSQGE1hqsnUMxNVUoO5oE7pdR+tg88+Ak98NdNkH4uEVc7+VDondcEB4yNRe8n77Sz2H1e8sOkKf43pItJ4gWzvVfvE2Envu0U8A3fh8LCGuqIjf76hb1ZLYmbFuKGdP10Pf907UAoWnKY00GiOb/27jAyGq5FZWZmTOpx5TmccCAwEAAaOCEpUwghKRMIISjQYJKoZIhvhNAQ0BBIISfgMAAgAAAAAACQAOAJOacjP3nEyplAoNs5V/BgeIL0Uz1CNk/bBW1wtZtSfkAAAAAAsLEA///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAA5wAAAAAAAAAvdFwL+ypITLCBZS84l84YF2KjDD7s0TIJ/h9YRCZnrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAg9cZ533qyhRw9rr2Kk13QwPImdtpAg+ccO4d/AjHzp4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAj21j+hsTAYc7WKWUx7FyGQn/rh3JxvIxbJ9BmWjaXnUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMoQAABeUvhg7JP8s0SjlrWxmOfiS+vOcKIFmjwCKtTPT1b4Nr9vnWTBaJPpUkh4TBqUe2ekdfxwlb0/iAeh/joZTu0XHGS8suPfhhAOf9eg/UgluGAWfeW4aL2hfLzMyr9uqVivFiBkIJuzW+JScjCfh3j6F7ZrwvkruoeWKWBlBE8ovwsLEA///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABUAAAAAAAAA5wAAAAAAAAAZKqUM4cDO8DzPiee1sWsNeXj1wrHtz3dNh3AugVTYvwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAjE9XddeWUD6WE393xoqCmgBWrI3tcBQLCBsJRJDFe/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHUqwU39Xqk888rBEYgDIRLpX+loYhlqy1f1rhwT61XUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIi6q4EMqukZUc/jyiInVYKKxjibFUxBefk/JW2VTFXjxCsIYg9JeLFxT11A9dp0zenxKzO7okYK2+XOuriGXmEgAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fBQBiDgAALS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUU5RENDQkptZ0F3SUJBZ0lWQU5nOVFrdHVnTm91SEVyTFp3TTZ0MGF3L2pZQ01Bb0dDQ3FHU000OUJBTUMKTUhBeElqQWdCZ05WQkFNTUdVbHVkR1ZzSUZOSFdDQlFRMHNnVUd4aGRHWnZjbTBnUTBFeEdqQVlCZ05WQkFvTQpFVWx1ZEdWc0lFTnZjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFCkNBd0NRMEV4Q3pBSkJnTlZCQVlUQWxWVE1CNFhEVEl6TURReU5qRTNNakkwTUZvWERUTXdNRFF5TmpFM01qSTAKTUZvd2NERWlNQ0FHQTFVRUF3d1pTVzUwWld3Z1UwZFlJRkJEU3lCRFpYSjBhV1pwWTJGMFpURWFNQmdHQTFVRQpDZ3dSU1c1MFpXd2dRMjl5Y0c5eVlYUnBiMjR4RkRBU0JnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEClZRUUlEQUpEUVRFTE1Ba0dBMVVFQmhNQ1ZWTXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBUVoKWWF6QzYzcDg1Um5TeFJyQ2tLRHQ4bitPUXR0UE5naUxLRDJzRDBUclZ6bUFheVZ5WXZ3OW5pbEE0dTU0ZTNaaQo2U2RkQWY1eGpzVlRuQXJPQUZQMG80SUREakNDQXdvd0h3WURWUjBqQkJnd0ZvQVVsVzlkemIwYjRlbEFTY25VCjlEUE9BVmNMM2xRd2F3WURWUjBmQkdRd1lqQmdvRjZnWElaYWFIUjBjSE02THk5aGNHa3VkSEoxYzNSbFpITmwKY25acFkyVnpMbWx1ZEdWc0xtTnZiUzl6WjNndlkyVnlkR2xtYVdOaGRHbHZiaTkyTXk5d1kydGpjbXcvWTJFOQpjR3hoZEdadmNtMG1aVzVqYjJScGJtYzlaR1Z5TUIwR0ExVWREZ1FXQkJSVjdBYUZ3d1J6QmhsQnBoTm5iL0lsClN2N2RYREFPQmdOVkhROEJBZjhFQkFNQ0JzQXdEQVlEVlIwVEFRSC9CQUl3QURDQ0Fqc0dDU3FHU0liNFRRRU4KQVFTQ0Fpd3dnZ0lvTUI0R0NpcUdTSWI0VFFFTkFRRUVFSE5nNVdZek5TVHkvWGNGWW9kU09lQXdnZ0ZsQmdvcQpoa2lHK0UwQkRRRUNNSUlCVlRBUUJnc3Foa2lHK0UwQkRRRUNBUUlCQ3pBUUJnc3Foa2lHK0UwQkRRRUNBZ0lCCkN6QVFCZ3NxaGtpRytFMEJEUUVDQXdJQkF6QVFCZ3NxaGtpRytFMEJEUUVDQkFJQkF6QVJCZ3NxaGtpRytFMEIKRFFFQ0JRSUNBUDh3RVFZTEtvWklodmhOQVEwQkFnWUNBZ0QvTUJBR0N5cUdTSWI0VFFFTkFRSUhBZ0VBTUJBRwpDeXFHU0liNFRRRU5BUUlJQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlKQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlLCkFnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJTEFnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJTUFnRUFNQkFHQ3lxR1NJYjQKVFFFTkFRSU5BZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSU9BZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSVBBZ0VBTUJBRwpDeXFHU0liNFRRRU5BUUlRQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlSQWdFTk1COEdDeXFHU0liNFRRRU5BUUlTCkJCQUxDd01ELy84QUFBQUFBQUFBQUFBQU1CQUdDaXFHU0liNFRRRU5BUU1FQWdBQU1CUUdDaXFHU0liNFRRRU4KQVFRRUJnQmdhZ0FBQURBUEJnb3Foa2lHK0UwQkRRRUZDZ0VCTUI0R0NpcUdTSWI0VFFFTkFRWUVFTXpwQ0JSeQpOZE5Kb2VWVnVoM2RkZ2d3UkFZS0tvWklodmhOQVEwQkJ6QTJNQkFHQ3lxR1NJYjRUUUVOQVFjQkFRSC9NQkFHCkN5cUdTSWI0VFFFTkFRY0NBUUgvTUJBR0N5cUdTSWI0VFFFTkFRY0RBUUgvTUFvR0NDcUdTTTQ5QkFNQ0Ewa0EKTUVZQ0lRQ2h6RDA4SXovZ2pSbzl0aUVkZU5JVzVlaHhJNEMzSDdaekdGQ3c1NXp3ZmdJaEFPYkhBR05NUWxEVwoyZmphRENxMEtpQmJyU3VsUm5Eeno4aVpzdVM2YU9EbwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDbGpDQ0FqMmdBd0lCQWdJVkFKVnZYYzI5RytIcFFFbkoxUFF6emdGWEM5NVVNQW9HQ0NxR1NNNDlCQU1DCk1HZ3hHakFZQmdOVkJBTU1FVWx1ZEdWc0lGTkhXQ0JTYjI5MElFTkJNUm93R0FZRFZRUUtEQkZKYm5SbGJDQkQKYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CTVFzdwpDUVlEVlFRR0V3SlZVekFlRncweE9EQTFNakV4TURVd01UQmFGdzB6TXpBMU1qRXhNRFV3TVRCYU1IQXhJakFnCkJnTlZCQU1NR1VsdWRHVnNJRk5IV0NCUVEwc2dVR3hoZEdadmNtMGdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnMKSUVOdmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeApDekFKQmdOVkJBWVRBbFZUTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTlNCLzd0MjFsWFNPCjJDdXpweHc3NGVKQjcyRXlER2dXNXJYQ3R4MnRWVExxNmhLazZ6K1VpUlpDbnFSN3BzT3ZncUZlU3hsbVRsSmwKZVRtaTJXWXozcU9CdXpDQnVEQWZCZ05WSFNNRUdEQVdnQlFpWlF6V1dwMDBpZk9EdEpWU3YxQWJPU2NHckRCUwpCZ05WSFI4RVN6QkpNRWVnUmFCRGhrRm9kSFJ3Y3pvdkwyTmxjblJwWm1sallYUmxjeTUwY25WemRHVmtjMlZ5CmRtbGpaWE11YVc1MFpXd3VZMjl0TDBsdWRHVnNVMGRZVW05dmRFTkJMbVJsY2pBZEJnTlZIUTRFRmdRVWxXOWQKemIwYjRlbEFTY25VOURQT0FWY0wzbFF3RGdZRFZSMFBBUUgvQkFRREFnRUdNQklHQTFVZEV3RUIvd1FJTUFZQgpBZjhDQVFBd0NnWUlLb1pJemowRUF3SURSd0F3UkFJZ1hzVmtpMHcraTZWWUdXM1VGLzIydWFYZTBZSkRqMVVlCm5BK1RqRDFhaTVjQ0lDWWIxU0FtRDV4a2ZUVnB2bzRVb3lpU1l4ckRXTG1VUjRDSTlOS3lmUE4rCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqekNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdORFV4TUZvWERUUTVNVEl6TVRJek5UazFPVm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU9XLzVRa1IrUzlDaVNEY05vb3dMdVBSTHNXR2YvWWk3R1NYOTRCZ3dUd2cKQWlFQTRKMGxySG9NcytYbzVvL3NYNk85UVd4SFJBdlpVR09kUlE3Y3ZxUlhhcUk9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KADALBgkqhkiG9w0BAQsDggGBAIAdtEV1Vzsfdy72EGununUaTA3B3FgRtQoohHxUkpS/gC63XECFRMp8BN5XaOhaga3uVgtWUKJueqD5xDM3jeZ6Sr1+WMOnyw4gytFB0fwFNKFu2P3RDhBAKNqcxjbezSIW/9HglOikqfF4kGIFnCy5Sps6w8nz82fKwBSvAR4EcQ8qVndxHph8w/xMxJjvBgMA9NhKymO5Nt/dPbTK9cbxl2mJ1Se07jsAkDTZe5xm+5plAvng/uPyrbsCrYbQG8CdtILeRbE8eDDNVx5EhyfiSf3qxi+ST5uPc2YX46+Uw/ukx+1sxp58lTGE9eQsf3YBFrIk4pTvBpiuTGu8yL8gYnTEUUH9LKVhM41BOeW4Rj2CClTB3fSo5peeHKpBMOQmwzWB2aEjD5FljkOmvWrYXaWWRCu6/SDgLk/vNghYPtn252mqdhcE+Vbo8W9O/SSZc+C2C96mrglKsUg8l+rXL2X+oLRfvZz5BQuBp3VehQRctIxLImLhthpsa209OA=="],"alg": "RS256"}]}
  ```

### Client-side compilation

```shell
cd client
cargo build
```

### Client-side running

```shell
cargo run
```

- The client receives requests from users carrying access tokens at `https://127.0.0.1:9999/api` and checks whether the access token is valid to decide whether to provide the user with access to a specific resource.

  - Request example

  ```shell
  curl -k -X GET "https://127.0.0.1:9999/api" --header 'authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9vVStqNDNPSFZBNTQwcGZsZXBoamVja29kL044Zy8yWnZtS1ROVm5JcU09In0.eyJpc3MiOiJlbmNsYXZlIGF1dGhvcml6YXRpb24iLCJhdWQiOlsiaHR0cHM6Ly9leGFtcGxlLmNvbS9zZXJ2ZXIxLWFwaSIsImh0dHBzOi8vZXhhbXBsZS5jb20vc2VydmVyMi1hcGkiXSwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMDcxODYzMjM2OTA4MjYxMzM3NDYiLCJpYXQiOjE2OTU4OTA4MzMsImV4cCI6MTY5NTg5NDQzMywic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOmFkbWluIiwiY2xpZW50X2lkIjoiSU1JcHJkUDRxZlN1S0FOZXZXa0p5aEc1Rjd3ZUVHVDAifQ.UjawxSHgN93USOfiiK9fI5wcvQwvnZwhjaLwEvN8qBfdGm3St_APIFmP9EcxhVtVC8x98vFy7NlzYbnDHoGwxUX-a3vL5ji79rfPAGej4KV4FfdS1UrUpEtYynWTpY0UNh__Bqyct1XRVDhnCwIJxcppz096ivAKCC4h4YOQCNzqaCB4G5ScpNxWP2uhz-mdRih7iIU0tcO3IQFRWwMGEexeFGPbPvelcZ7RJXlhCHpz0-i3SUc5actY-ItEyDYnjtiIlaai2DIxjERRUIA7NnvaxKav59PwHmXMnjD2cA__IvR0HiGrbrksh7E0EUulbqxkNeQ1zKkm-CjVdLhPWaVNRtOHyotl6H7cgQkRB4OnMrs0R1LO6G-kd78xGdX_Wn9UGMkKFmYrFb5BEC2YJvM1KgKXkkIWc739j8pt9eerDUYXqODmeMLScSv-KN7JcbHVCt0yzQuzIk0rf9LX73QlSGYgDkJIa_XzHzom2RN80MRtsAMyLEiknH7jQKBf'
  ```

  - Request Response Example

  ```
  Access Token parsed successfully
  ```

- The client will receive the access token according to the code in the specified URL to the specified endpoint request jwks, using jwk to verify the access token is correct.

The jwk provided in the x509 format certificate contains intel sgx remote proof of Quote. Quote includes a jwk token in the public key hash value; the client will verify Quote first to ensure that the public key in the jwk is credible and then use the public key provided in the jwk to verify the access token for resource authorization.