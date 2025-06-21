#![deny(clippy::all)]
mod types;
use bincode;
use hex::FromHex;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::Deserialize;
use std::time::Duration;
use tlsn_core::{
  presentation::{Presentation, PresentationOutput},
  CryptoProvider,
};
use types::{PresentationJSON, VerificationResult};

#[napi]
pub fn verify_presentation(json: String) -> Result<VerificationResult> {
  let presentation_json = PresentationJSON::from_json(&json)
  .map_err(|e| Error::from_reason(format!("Invalid JSON: {}", e)))?;
println!("Presentation data: {:?}", presentation_json.data);

  // Deserialize the hex-encoded serialized Presentation.
let presentation = presentation_json
  .to_presentation()
  .map_err(|e| Error::from_reason(format!("Presentation deserialization failed: {}", e)))?;

  // Extract the verifying key.
let verifying_key = hex::encode(presentation.verifying_key().data.clone());

  let PresentationOutput {
    server_name,
    connection_info,
    transcript,
    // extensions, // Optionally, verify any custom extensions from prover/notary.
    ..
  } = presentation.verify(&CryptoProvider::default()).unwrap();

  // The time at which the connection was started.
  let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
  let server_name = server_name.unwrap();
  let mut partial_transcript = transcript.unwrap();
  // Set the unauthenticated bytes so they are distinguishable.
  partial_transcript.set_unauthed(b'X');

  let sent = partial_transcript.sent_unsafe().to_vec();
  let recv = partial_transcript.received_unsafe().to_vec();

  Ok(VerificationResult {
    server_name: server_name.to_string(),
    verifying_key: verifying_key,
    sent: sent,
    recv: recv,
    time: time.to_string(),
  })
}
