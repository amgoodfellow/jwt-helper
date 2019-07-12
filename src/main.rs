extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate clap;
extern crate base64;
extern crate regex;

use jwt::{decode, decode_header, Validation};
use regex::Regex;
use std::error::Error;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    name: String,
    sub: String,
    iat: i64,
}

fn is_jwt(token: &str) -> bool {
    let re = Regex::new(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$").unwrap();
    re.is_match(token)
}

fn get_jwt_info(token: &str) {
    if is_jwt(token) {
        let token_vec: Vec<&str> = token.split(".").collect();
        let decoded_header = base64::decode(token_vec.get(0).unwrap()).unwrap();
        let decoded_claims = base64::decode(token_vec.get(1).unwrap()).unwrap();
        println!("{:#?}", std::str::from_utf8(&decoded_header).unwrap());
        println!("{:#?}", std::str::from_utf8(&decoded_claims).unwrap());
    } else {
        println!("Please input a valid token");
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();

    let password = matches.value_of("password").unwrap_or("CHANGEME");
    let signing_key = matches.value_of("signing_key").unwrap_or("CHANGEME");

    match matches.subcommand() {
        ("info", Some(sub_param)) => {
            let token = sub_param.value_of("token").unwrap();
            get_jwt_info(token);
        }
        ("verify", Some(sub_param)) => {
            // Get token
            let token = sub_param.value_of("token").expect("No token provided");
            let ignore_expiration = sub_param.is_present("ignore_exp");

            // Extract necessary info from header
            let header = decode_header(&token).unwrap();
            let mut validation = Validation::new(header.alg);
            validation.validate_exp = !ignore_expiration;

            // Attempt to verify
            let result = decode::<Claims>(&token, signing_key.as_ref(), &validation);

            let result = match result {
                Ok(jwt) => jwt,
                Err(error) => {
                    let description = String::from(error.description());
                    if description == "expired signature" {
                        println!("The token's signature has expired. To run again without verifying signature, run the following:\n");
                        println!(
                            "jwt-helper -k {} verify {} --ignore-exp\n",
                            signing_key, token
                        );
                    } else if description == "invalid signature" && signing_key == "CHANGEME" {
                        println!("jwt-helper is still using the default signature. Did you mean to change it?\n");
                        println!("jwt-helper -k <signing-key> verify <token>\n");
                    } else {
                        println!("Verification error. To see contents without verifying, try `jwt-token info <token>`");
                        println!("{}\n", description);
                    }
                    std::process::exit(1);
                }
            };

            println!("{:?}", result);
        }
        ("decrypt", Some(sub_param)) => {
            let token = sub_param.value_of("token").unwrap();
            //let base_64 = base64::decode(token).unwrap();

            println!("Decrypting token flow");
        }
        _ => println!("Oof"),
    }
}
