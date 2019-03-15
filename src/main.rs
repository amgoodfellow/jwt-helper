extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;
extern crate base64;
#[macro_use]
extern crate clap;

use std::io;
use jwt::{encode, decode, Header, Algorithm, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    telephoneNumber: String,
    gid: String,
    mail: String,
    displayName: String,
    givenName: String,
    uid: String,
    pidm: String
}

fn main() {
    let yaml = load_yaml!("cli.yml");
    let matches = clap::App::from_yaml(yaml).get_matches();

    let password = matches.value_of("password").unwrap_or("CHANGEME");
    let signing_key = matches.value_of("signing_key").unwrap_or("CHANGEME");
    let algorithm = matches.value_of("algorithm").unwrap_or("HS512");

    if let Some(matches) = matches.subcommand_matches("verify") {
        let token = matches.value_of("token").unwrap();
        let base_64 = base64::decode(token).unwrap();
        let validation = Validation::new(Algorithm::HS512);

        let result = decode::<Claims>(&token, &base_64, &validation);
        println!("{:?}", result);
    }

    if let Some(matches) = matches.subcommand_matches("decrypt") {
        let token = matches.value_of("token").unwrap();

    }

}
