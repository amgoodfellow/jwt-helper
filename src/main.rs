extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate clap;
extern crate base64;

use std::io;
use jwt::{encode, decode, Header, Algorithm, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    displayName: String,
    uid: String,
    pidm: String
}

fn get_algorithm(param: Option<&str>) -> Algorithm {
    match param {
        Some("HS256") => Algorithm::HS256,
        Some("HS384") => Algorithm::HS384,
        Some("HS512") => Algorithm::HS512,
        _ => {
            println!("Algorithm not specified or incorrect - defaulting to HS256");
            Algorithm::HS256
        }
    }
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();

    let password = matches.value_of("password").unwrap_or("CHANGEME");
    let signing_key = matches.value_of("signing_key").unwrap_or("CHANGEME");
    let algorithm = get_algorithm(matches.value_of("algorithm"));



    match matches.subcommand() {
        ("verify", Some(blob)) => {
            let token = blob.value_of("token").unwrap();
            let base_64 = base64::decode(token).unwrap();
            let validation = Validation::new(Algorithm::HS512);

            let result = decode::<Claims>(&token, &base_64, &validation);
            println!("Verifying token flow");
        }
        ("decrypt", Some(blob)) => {
            let token = blob.value_of("token").unwrap();
            let base_64 = base64::decode(token).unwrap();

            println!("Decrypting token flow");
        }
        _ => println!("Oof")
    }

}
