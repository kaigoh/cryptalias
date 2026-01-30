use base64::Engine;
use reqwest::blocking::Client;
use serde::Deserialize;
use ed25519_dalek::{Signature, VerifyingKey};
use chrono::{DateTime, Utc};

#[derive(Deserialize)]
struct WellKnownConfig {
    resolver: Resolver,
    key: Option<JwkKey>,
}

#[derive(Deserialize)]
struct Resolver {
    resolver_endpoint: String,
}

#[derive(Deserialize)]
struct JwkKey {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Deserialize)]
struct ResolvedPayload {
    address: String,
    expires: Option<String>,
}

// Resolve alias$domain into a wallet address and verify the JWS signature.
pub fn resolve_address(ticker: &str, alias: &str) -> Result<String, Box<dyn std::error::Error>> {
    if ticker.is_empty() || alias.is_empty() {
        return Err("ticker and alias are required".into());
    }
    let ticker_clean = normalize_ticker(ticker);
    if ticker_clean.is_empty() {
        return Err("ticker and alias are required".into());
    }
    if let Some(prefix) = parse_ticker_prefix(alias)? {
        if prefix != ticker_clean {
            return Err(format!(
                "ticker prefix \"{}\" does not match \"{}\"",
                prefix, ticker_clean
            )
            .into());
        }
    }
    let domain = parse_domain(alias)?;

    let cfg_url = format!(
        "https://{}/.well-known/cryptalias/configuration",
        domain
    );

    let client = Client::new();
    let cfg: WellKnownConfig = client
        .get(&cfg_url)
        .header("Accept", "application/json")
        .send()?
        .error_for_status()?
        .json()?;

    let resolver = cfg.resolver.resolver_endpoint.trim_end_matches('/');
    if resolver.is_empty() {
        return Err("missing resolver_endpoint in configuration".into());
    }
    let jwk = cfg.key.ok_or("missing key in configuration")?;

    let resolve_url = format!(
        "{}/_cryptalias/resolve/{}/{}",
        resolver,
        urlencoding::encode(&ticker_clean),
        urlencoding::encode(alias)
    );

    let jws = client
        .get(&resolve_url)
        .header("Accept", "application/jose")
        .send()?
        .error_for_status()?
        .text()?;

    let payload = verify_jws_and_decode_payload(&jws, &jwk)?;
    enforce_expires(&payload)?;
    Ok(payload.address)
}

fn parse_domain(alias: &str) -> Result<&str, Box<dyn std::error::Error>> {
    let idx = alias
        .rfind('$')
        .ok_or("alias must be in the format [ticker:]alias$domain")?;
    if idx == alias.len() - 1 {
        return Err("alias must be in the format [ticker:]alias$domain".into());
    }
    Ok(&alias[idx + 1..])
}

fn parse_ticker_prefix(alias: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let idx = alias
        .rfind('$')
        .ok_or("alias must be in the format [ticker:]alias$domain")?;
    if idx == alias.len() - 1 {
        return Err("alias must be in the format [ticker:]alias$domain".into());
    }
    let left = &alias[..idx];
    let colon = match left.find(':') {
        Some(pos) => pos,
        None => return Ok(None),
    };
    if colon == 0 || colon == left.len() - 1 || left[colon + 1..].contains(':') {
        return Err("invalid format (expected [ticker:]alias[+tag]$domain)".into());
    }
    Ok(Some(left[..colon].to_lowercase()))
}

fn normalize_ticker(value: &str) -> String {
    value.trim().to_lowercase()
}

fn decode_jws_payload(jws: &str) -> Result<ResolvedPayload, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWS format".into());
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])?;
    let payload: ResolvedPayload = serde_json::from_slice(&payload_bytes)?;
    if payload.address.is_empty() {
        return Err("missing address in JWS payload".into());
    }
    Ok(payload)
}

fn verify_jws_and_decode_payload(
    jws: &str,
    jwk: &JwkKey,
) -> Result<ResolvedPayload, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid JWS format".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2])?;
    let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&jwk.x)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes)?;
    let sig = Signature::from_slice(&sig_bytes)?;

    pk.verify_strict(signing_input.as_bytes(), &sig)?;
    decode_jws_payload(jws)
}

fn enforce_expires(payload: &ResolvedPayload) -> Result<(), Box<dyn std::error::Error>> {
    let expires = payload
        .expires
        .as_ref()
        .ok_or("missing expires in JWS payload")?;
    let dt = DateTime::parse_from_rfc3339(expires)?;
    let now: DateTime<Utc> = Utc::now();
    if dt.with_timezone(&Utc) <= now {
        return Err("resolved address has expired".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    struct TestData {
        jws: String,
        jwk: JwkKey,
        payload: ResolvedPayload,
    }

    fn load_test_data() -> TestData {
        let path = PathBuf::from("../testdata/jws.json");
        let data = fs::read_to_string(path).expect("read test data");
        serde_json::from_str(&data).expect("parse test data")
    }

    #[test]
    fn test_decode_jws_payload() {
        let td = load_test_data();
        let payload = decode_jws_payload(&td.jws).unwrap();
        assert_eq!(payload.address, td.payload.address);
    }

    #[test]
    fn test_verify_jws() {
        let td = load_test_data();
        let payload = verify_jws_and_decode_payload(&td.jws, &td.jwk).unwrap();
        assert_eq!(payload.address, td.payload.address);
    }
}
