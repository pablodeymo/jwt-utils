use anyhow::{anyhow, Result};
use chrono::prelude::*;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

pub fn calculate_jwt_with_username(userid: &str, username: &str, secret: &[u8]) -> Result<String> {
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims<'a> {
        sub: &'a str, // (subject): Subject of the JWT (the user)
        name: &'a str,
        iat: i64,
    }

    let local: DateTime<Local> = Local::now();

    let jwt_claim = Claims {
        sub: userid,
        name: username,
        iat: local.timestamp(),
    };

    // jwt_claim is a struct that implements Serialize
    // This will create a JWT using HS256 as algorithm
    encode(
        &Header::default(),
        &jwt_claim,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| anyhow!("Error generating JWT. {}", e))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
