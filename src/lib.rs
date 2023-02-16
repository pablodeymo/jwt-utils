use anyhow::{anyhow, Result};
use chrono::prelude::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims<'a> {
    sub: &'a str, // (subject): Subject of the JWT (the user)
    name: &'a str,
    iat: i64,
    exp: usize,
}

impl<'a> Claims<'a> {
    pub fn new(userid: &'a str, username: &'a str, exp: usize) -> Claims<'a> {
        let local: DateTime<Local> = Local::now();
        Claims {
            sub: userid,
            name: username,
            iat: local.timestamp(),
            exp,
        }
    }
}

pub fn encode_jwt_with_username(userid: &str, username: &str, secret: &[u8]) -> Result<String> {
    let jwt_claim = Claims::new(userid, username, 10_000_000_000);

    // jwt_claim is a struct that implements Serialize
    // This will create a JWT using HS256 as algorithm
    encode(
        &Header::default(),
        &jwt_claim,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| anyhow!("Error generating JWT. {e}"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeserializedClaims {
    pub sub: Option<String>, // (subject): Subject of the JWT (the user)
    pub name: Option<String>,
    pub iat: i64,
}

impl DeserializedClaims {
    pub fn decode_jwt_token(token: &str, secret: &[u8]) -> Result<Self> {
        // Claims is a struct that implements Deserialize
        decode::<DeserializedClaims>(
            token,
            &DecodingKey::from_secret(secret),
            &Validation::new(Algorithm::HS256),
        )
        .map(|v| v.claims)
        .map_err(|e| anyhow!("Error decoding JWT token. {e}"))
    }
}
