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


impl PresentationJSON {
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn to_presentation(&self) -> Result<Presentation, bincode::Error> {
        println!("Hex length: {}", self.data.len());

        let raw = hex::decode(&self.data)
            .map_err(|e| bincode::ErrorKind::Custom(format!("Hex decode failed: {}", e)))?;
        println!("Raw data length: {}", raw.len());
        bincode::deserialize(&raw)
    }

    
}
