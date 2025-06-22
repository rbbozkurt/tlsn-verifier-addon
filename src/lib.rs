#![deny(clippy::all)]
mod types;
use bincode;
use hex::FromHex;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::Deserialize;
use std::{fs, time::Duration};
use tlsn_core::{
  presentation::{Presentation, PresentationOutput},
  CryptoProvider,
};

use types::{
  InputPresentationData, InputProofJson, PresentationJSON, VerificationOutput, VerificationResult,
};

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

#[napi]
pub fn verify_presentation_from_file(path: String) -> Result<VerificationResult> {
  let file_content = fs::read_to_string(&path)
    .map_err(|e| Error::from_reason(format!("Failed to read file {}: {}", path, e)))?;
  println!("File content: {}", file_content);
  verify_presentation(file_content)
}

#[napi]
pub fn verify_presentation_in_another_format(path: String) -> Result<VerificationOutput> {
  // This function is a placeholder for any additional processing or conversion
  // that might be needed for different formats.

  let proof_json = fs::read_to_string(&path)
    .map_err(|e| Error::from_reason(format!("Failed to read file {}: {}", path, e)))?;
  let mut output: VerificationOutput = VerificationOutput {
    is_valid: false,
    server_name: String::new(),
    score: None,
    error: None,
  };
  let input: InputProofJson = match serde_json::from_str(&proof_json) {
    Ok(v) => v,
    Err(e) => {
      output.error = Some(format!("Failed to parse outer JSON: {}", e));

      return Ok(output);
    }
  };
  println!("Input data: {:?}", input.presentation_json);
  // Hex-decode bincode payload
  let proof_bytes = match hex::decode(&input.presentation_json.data) {
    Ok(b) => b,
    Err(e) => {
      output.error = Some(format!("Failed to hex-decode data: {}", e));
      return Ok(output);
    }
  };

  // Bincode-deserialize into Presentation
  let tlsn_presentation: Presentation = match bincode::deserialize(&proof_bytes) {
    Ok(p) => p,
    Err(e) => {
      output.error = Some(format!("Bincode deserialize failed: {}", e));
      return Ok(output);
    }
  };

  // All checks passed: verify Presentation
  let provider = CryptoProvider::default();
  let pres_out: PresentationOutput = match tlsn_presentation.verify(&provider) {
    Ok(o) => o,
    Err(e) => {
      output.error = Some(format!("Presentation.verify() failed: {:?}", e));
      return Ok(output);
    }
  };

  // Extract server_name
  if let Some(sn) = pres_out.server_name {
    output.server_name = sn.to_string();
  }
  output.is_valid = true;
  // Extract score if present
  if let Some(transcript) = pres_out.transcript {
    if let Ok(s) = std::str::from_utf8(transcript.received_unsafe()) {
      if let Some(val) = s.split("score=").nth(1) {
        output.score = val
          .split(&['&', '"'][..])
          .next()
          .and_then(|num| num.parse().ok());
      }
    }
  }

  // Examplary: enforce minimum score threshold
  match output.score {
    Some(score_val) if score_val > 5 => {
      // OK: above threshold
      return Ok(output);
    }
    Some(score_val) => {
      output.error = Some(format!(
        "Score {} is below the required threshold of 5",
        score_val
      ));
      output.is_valid = false;
      return Ok(output);
    }
    None => {
      output.error = Some("Score missing or could not be parsed".to_string());
      output.is_valid = false;
      return Ok(output);
    }
  }
}
