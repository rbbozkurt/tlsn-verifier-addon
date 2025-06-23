use std::{env, fs, process};
use serde::Deserialize;
use hex;
use bincode;
use chrono::{DateTime, Utc, NaiveDateTime, TimeZone};
use tlsn_core::{
    presentation::{Presentation, PresentationOutput},
    CryptoProvider,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PresentationJSON {
    version: String,
    data: String,
    meta: Meta,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    notary_url: String,
    websocket_proxy_url: Option<String>,
}

/// Parse JSON → clean hex → bincode → Presentation
fn to_presentation(json_str: &str) -> Result<Presentation, Box<dyn std::error::Error>> {
    let pres_json: PresentationJSON = serde_json::from_str(json_str)?;
    // remove newlines/spaces from the hex string
    let clean_hex: String = pres_json
        .data
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let raw = hex::decode(&clean_hex)?;
    let presentation: Presentation = bincode::deserialize(&raw)?;
    Ok(presentation)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) get the JSON file path
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("Usage: tlsn-verifier <presentation.json>");
            process::exit(1);
        });

    // 2) read the file
    let json = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path, e))?;
    
    // 3) decode → Presentation
    let presentation = to_presentation(&json)
        .map_err(|e| format!("Failed to parse/deserialize presentation: {}", e))?;
    
    // 4) verify
    let mut pres_out: PresentationOutput = presentation
        .verify(&CryptoProvider::default())
        .map_err(|e| format!("Verification error: {:?}", e))?;
    
    // 5) server name
    let server_name = pres_out
        .server_name
        .map(|sn| sn.to_string())
        .unwrap_or_else(|| "<no server_name>".into());
    
    // 6) timestamp → RFC3339
    let secs = pres_out.connection_info.time as i64;
    let naive = NaiveDateTime::from_timestamp_opt(secs, 0)
        .ok_or("Invalid timestamp")?;
    let dt: DateTime<Utc> = Utc.from_utc_datetime(&naive);
    
    // 7) transcript bytes
    let mut transcript = pres_out
        .transcript
        .ok_or("Missing transcript")?;
    transcript.set_unauthed(b'X');
    let sent = transcript.sent_unsafe();
    let recv = transcript.received_unsafe();
    
    // 8) print it out
    println!("\nPresentation verified!");
    println!("Server Name      : {}", server_name);
    println!("Verification Time: {}", dt.to_rfc3339());
    println!("Transcript Sent  : {}", hex::encode(sent));
    println!("Transcript Recv  : {}", hex::encode(recv));
    
    Ok(())
}
