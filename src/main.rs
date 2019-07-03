extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate clap;
extern crate base64;

use jwt::{decode, decode_header, encode, Algorithm, Header, Validation};
use std::io;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    name: String,
    sub: String,
    iat: i64,
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();

    let password = matches.value_of("password").unwrap_or("CHANGEME");
    let signing_key = matches.value_of("signing_key").unwrap_or("CHANGEME");

    match matches.subcommand() {
        ("info", Some(sub_param)) => {
            let token = sub_param.value_of("token").unwrap();
            let token_vec : Vec<&str> = token.split(".").collect();
            let decoded_header = base64::decode(token_vec.get(0).unwrap()).unwrap();
            let decoded_claims = base64::decode(token_vec.get(1).unwrap()).unwrap();
            println!("{:?}", std::str::from_utf8(&decoded_header).unwrap());
            println!("{:?}", std::str::from_utf8(&decoded_claims).unwrap());
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
                Err(error) => panic!("{:?}", error.into_kind()),
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
