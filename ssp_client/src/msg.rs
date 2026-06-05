use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

// Decrypted incoming peer message piped to application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Msg {
    pub from: EndpointId,
    pub recvtime: SystemTime,
    pub data: Vec<u8>,
}

impl Msg {
    pub fn new(data: Vec<u8>, from: EndpointId) -> Msg {
        Self {
            from,
            recvtime: SystemTime::now(),
            data,
        }
    }
}

// Plaintext payload, gets encrypted inside SLPMsgData::Data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgPayload {
    pub from: EndpointId,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SLPMsgData {
    // Application data
    Data {
        data: Vec<u8>,
        nonce: [u8; 12],
    },
    // Fragment of a chunked message
    Chunk {
        from: EndpointId,
        id: u64,
        index: u16,
        total: u16,
        payload: Vec<u8>,
    },
    NewGame {
        from: EndpointId,
        newseed: [u8; 32],
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SLPMsg {
    pub body: SLPMsgData,
    pub signature: Vec<u8>,
}

impl SLPMsg {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    pub fn new_signed(body: SLPMsgData, secret_key: &iroh::SecretKey) -> Self {
        let body_bytes = bincode::serialize(&body).expect("Serialization of body must succeed");
        let signature = secret_key.sign(&body_bytes).to_bytes().to_vec();
        Self { body, signature }
    }

    pub fn verify(&self, from: &iroh::EndpointId) -> bool {
        let sig_bytes: [u8; 64] = match self.signature.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let body_bytes =
            bincode::serialize(&self.body).expect("Serialization of body must succeed");
        let sig = iroh::Signature::from_bytes(&sig_bytes);
        from.verify(&body_bytes, &sig).is_ok()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode::serialize must succeed")
    }
}
