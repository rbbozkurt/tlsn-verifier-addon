use serde::{Deserialize, Serialize};
use napi_derive::napi;
use tlsn_core::{
    presentation::{Presentation, PresentationOutput},
    CryptoProvider,
};
use std::ops::Deref;

use hex;
use bincode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationInput {
    pub presentation: PresentationJSON,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentationJSON {
    pub version: String,
    pub data: String, // hex-encoded serialized Presentation
    pub meta: Meta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub notary_url: String,
    pub websocket_proxy_url: Option<String>,
}

#[napi(object)]
pub struct VerificationResult {
    pub server_name: String,
    pub verifying_key: String,
    pub sent: Vec<u8>,
    pub recv: Vec<u8>,
    pub time: String,
}


#[derive(Debug, Serialize, Deserialize)]
#[napi(object)]
pub struct VerificationOutput {
    pub is_valid: bool,
    pub server_name: String,
    pub score: Option<i64>, // Change u64 to i64 for napi compatibility
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[napi(object)]
pub struct InputProofJson {
    #[serde(rename = "presentationJson")]
    pub presentation_json: InputPresentationData,
}

#[derive(Debug, Serialize, Deserialize)]
#[napi(object)]
pub struct InputPresentationData {
    pub version: String,
    pub data: String,
}


impl PresentationJSON {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn to_presentation(&self) -> Result<Presentation, bincode::Error> {
        println!("Hex length: {}", self.data.len());

        let raw = match hex::decode(&self.data){
            Ok(b) => b,
            Err(e) => {
                println!("Hex decode error: {}", e);
                return Err(bincode::Error::new(bincode::ErrorKind::Custom(e.to_string())));
            }
        };
        println!("Raw data length: {}", raw.len());
        let tlsn_presentation: Presentation = match bincode::deserialize(&raw) {
            Ok(p) => p,
            Err(e) => {
                println!("Bincode deserialize error: {}", e);
                return Err(bincode::Error::new(bincode::ErrorKind::Custom(e.to_string())));
            }
        };
        return Ok(tlsn_presentation);
    }

    
}
