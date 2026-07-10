#![cfg_attr(not(debug_assertions), allow(unused_variables))]

use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;

use iroh::endpoint::{Accepting, Connection};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh_gossip::net::Gossip;

use debug_print::debug_println;
use serde::{Deserialize, Serialize};

/// Current SSP protocol version. Incremented when breaking handshake/network
/// changes are made that old peers should not interoperate with.
pub const SSP_VERSION: [u8; 3] = [0, 1, 0];

// Min/preferred/max for handshake parameters
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParamRange {
    pub min: u64,
    pub preferred: u64,
    pub max: u64,
}

impl ParamRange {
    pub fn new(min: u64, preferred: u64, max: u64) -> Self {
        debug_assert!(min <= max, "ParamRange min must be <= max");
        Self {
            min,
            preferred: preferred.clamp(min, max),
            max,
        }
    }

    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let lo = self.min.max(other.min);
        let hi = self.max.min(other.max);
        if lo <= hi {
            let pref = self.preferred.min(other.preferred).clamp(lo, hi);
            Some(Self {
                min: lo,
                preferred: pref,
                max: hi,
            })
        } else {
            None
        }
    }
}

// Parameters used in handshake
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(C)]
pub struct HandshakeConfig {
    pub rollover: ParamRange,
    pub offset: ParamRange,
    pub slp_version_min: [u8; 3],
    pub slp_version_max: [u8; 3],
    pub ssp_version_min: [u8; 3],
    pub ssp_version_max: [u8; 3],
}

// Sent by joiner
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeOffer {
    pub config: HandshakeConfig,
    pub slp_version: [u8; 3],
    pub ssp_version: [u8; 3],
}

// Sent by host when offer is accepted
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeAccept {
    pub rollover: ParamRange,
    pub offset: ParamRange,
}

// Sent by host when offer is rejected
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HandshakeReject {
    pub reason: String,
}

/// Host to joiner response
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum HandshakeResponse {
    Accept(HandshakeAccept),
    Reject(HandshakeReject),
}

const MAX_HANDSHAKE_MSG: usize = 512;
pub const SSP_ALPN: &[u8] = b"ssp";

// State shared with GameNet required for incoming handshaking
#[derive(Debug)]
pub struct HandshakeState {
    pub config: HandshakeConfig,
    // Not in config as out of application control
    pub slp_version: [u8; 3],
    pub ssp_version: [u8; 3],

    // Valid parameter ranges for self and peers,
    // preferred is active value, only narrows
    // and does not expand upon leaving peers
    pub group_rollover: ParamRange,
    pub group_offset: ParamRange,
}

impl HandshakeState {
    pub fn new(config: HandshakeConfig, slp_version: [u8; 3], ssp_version: [u8; 3]) -> Self {
        Self {
            config,
            slp_version,
            ssp_version,
            group_rollover: config.rollover,
            group_offset: config.offset,
        }
    }

    // Evaluate incoming HandshakeOffer and update connection parameters
    pub fn evaluate_offer(&mut self, offer: HandshakeOffer) -> Result<HandshakeAccept, String> {
        // Check SSP protocol version compatibility (own version must fall in peer's range)
        let their_ssp_min = offer.config.ssp_version_min;
        let their_ssp_max = offer.config.ssp_version_max;
        if self.ssp_version < their_ssp_min || self.ssp_version > their_ssp_max {
            return Err(format!(
                "Your SSP version {}.{}.{} outside peer's accepted range [{}.{}.{}, {}.{}.{}]",
                self.ssp_version[0],
                self.ssp_version[1],
                self.ssp_version[2],
                their_ssp_min[0],
                their_ssp_min[1],
                their_ssp_min[2],
                their_ssp_max[0],
                their_ssp_max[1],
                their_ssp_max[2],
            ));
        }
        // Check peer's SSP version falls in our accepted range
        let my_ssp_min = self.config.ssp_version_min;
        let my_ssp_max = self.config.ssp_version_max;
        if offer.ssp_version < my_ssp_min || offer.ssp_version > my_ssp_max {
            return Err(format!(
                "Peer SSP version {}.{}.{} outside your accepted range [{}.{}.{}, {}.{}.{}]",
                offer.ssp_version[0],
                offer.ssp_version[1],
                offer.ssp_version[2],
                my_ssp_min[0],
                my_ssp_min[1],
                my_ssp_min[2],
                my_ssp_max[0],
                my_ssp_max[1],
                my_ssp_max[2],
            ));
        }
        let my_min = self.config.slp_version_min;
        let my_max = self.config.slp_version_max;
        if offer.slp_version < my_min || offer.slp_version > my_max {
            return Err(format!(
                "Peer SLP version {}.{}.{} outside your accepted range [{}.{}.{}, {}.{}.{}]",
                offer.slp_version[0],
                offer.slp_version[1],
                offer.slp_version[2],
                my_min[0],
                my_min[1],
                my_min[2],
                my_max[0],
                my_max[1],
                my_max[2],
            ));
        }

        let their_min = offer.config.slp_version_min;
        let their_max = offer.config.slp_version_max;
        if self.slp_version < their_min || self.slp_version > their_max {
            return Err(format!(
                "Your SLP version {}.{}.{} outside peer's accepted range [{}.{}.{}, {}.{}.{}]",
                self.slp_version[0],
                self.slp_version[1],
                self.slp_version[2],
                their_min[0],
                their_min[1],
                their_min[2],
                their_max[0],
                their_max[1],
                their_max[2],
            ));
        }

        // Narrow connection parameters
        let new_group_rollover = self
            .group_rollover
            .intersect(&offer.config.rollover)
            .ok_or_else(|| {
                format!(
                    "rollover range [{}, {}] does not overlap group window [{}, {}]",
                    offer.config.rollover.min,
                    offer.config.rollover.max,
                    self.group_rollover.min,
                    self.group_rollover.max,
                )
            })?;

        let new_group_offset = self
            .group_offset
            .intersect(&offer.config.offset)
            .ok_or_else(|| {
                format!(
                    "offset range [{}, {}] does not overlap group window [{}, {}]",
                    offer.config.offset.min,
                    offer.config.offset.max,
                    self.group_offset.min,
                    self.group_offset.max,
                )
            })?;
        self.group_rollover = new_group_rollover;
        self.group_offset = new_group_offset;
        Ok(HandshakeAccept {
            rollover: self.group_rollover,
            offset: self.group_offset,
        })
    }
}

use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct HandshakeGuard {
    gossip: Gossip,
    state: Arc<Mutex<HandshakeState>>,
    handshake_succ_tx: Option<tokio::sync::mpsc::UnboundedSender<(u64, u64)>>,
    discovery_cancel: CancellationToken,
    peer_connected_tx: tokio::sync::watch::Sender<bool>,
}

impl std::fmt::Debug for HandshakeGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeGuard").finish()
    }
}

impl HandshakeGuard {
    pub fn new(
        gossip: Gossip,
        state: Arc<Mutex<HandshakeState>>,
        handshake_succ_tx: Option<tokio::sync::mpsc::UnboundedSender<(u64, u64)>>,
        discovery_cancel: CancellationToken,
        peer_connected_tx: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self {
            gossip,
            state,
            handshake_succ_tx,
            discovery_cancel,
            peer_connected_tx,
        }
    }
}
pub fn accept_is_valid(config: HandshakeConfig, accept: &HandshakeAccept) -> bool {
    if accept.offset.preferred > config.offset.max || accept.offset.preferred < config.offset.min {
        return false;
    }
    if accept.rollover.preferred > config.rollover.max
        || accept.rollover.preferred < config.rollover.min
    {
        return false;
    }
    true
}

impl ProtocolHandler for HandshakeGuard {
    fn on_accepting(
        &self,
        accepting: Accepting,
    ) -> impl Future<Output = Result<Connection, AcceptError>> + Send {
        let state = self.state.clone();
        let handshake_succ_tx = self.handshake_succ_tx.clone();
        async move {
            let accept_started_at = tokio::time::Instant::now();
            let conn = accepting.await?;
            let remote = conn.remote_id();

            debug_println!(
                "{:?}: Incoming handshake (accept elapsed {:?})",
                remote,
                accept_started_at.elapsed()
            );

            let bi_res =
                tokio::time::timeout(std::time::Duration::from_secs(6), conn.accept_bi()).await;

            let (mut send, mut recv) = match bi_res {
                Ok(Ok(streams)) => {
                    debug_println!(
                        "{:?}: Accepted incoming bi stream after {:?}",
                        remote,
                        accept_started_at.elapsed()
                    );
                    streams
                }
                Ok(Err(e)) => {
                    return Err(AcceptError::from_err(e));
                }
                Err(_) => {
                    conn.close(1u32.into(), b"handshake timeout");
                    return Err(AcceptError::from_err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "handshake timeout",
                    )));
                }
            };

            let offer_bytes = recv
                .read_to_end(MAX_HANDSHAKE_MSG)
                .await
                .map_err(AcceptError::from_err)?;
            debug_println!(
                "{:?}: Read handshake offer after {:?} ({} bytes)",
                remote,
                accept_started_at.elapsed(),
                offer_bytes.len()
            );

            let offer: HandshakeOffer = serde_json::from_slice(&offer_bytes).map_err(|e| {
                AcceptError::from_err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid handshake offer: {e}"),
                ))
            })?;

            debug_println!(
                "{:?}: Offer for rollover={:?}, offset={:?}, slp_version={}.{}.{}, ssp_version={}.{}.{}",
                remote,
                offer.config.rollover,
                offer.config.offset,
                offer.slp_version[0],
                offer.slp_version[1],
                offer.slp_version[2],
                offer.ssp_version[0],
                offer.ssp_version[1],
                offer.ssp_version[2],
            );

            let (response, config_changed) = {
                let mut hs = state.lock().await;
                let old_rollover = hs.config.rollover.preferred;
                let old_offset = hs.config.offset.preferred;
                match hs.evaluate_offer(offer) {
                    Ok(accept) => {
                        let changed = accept.rollover.preferred != old_rollover
                            || accept.offset.preferred != old_offset;
                        (HandshakeResponse::Accept(accept), changed)
                    }
                    Err(reason) => {
                        debug_println!("{:?}: Rejected because {}", remote, reason);
                        (HandshakeResponse::Reject(HandshakeReject { reason }), false)
                    }
                }
            };

            let resp_bytes = serde_json::to_vec(&response).map_err(|e| {
                AcceptError::from_err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("failed to serialize response: {e}"),
                ))
            })?;

            send.write_all(&resp_bytes)
                .await
                .map_err(AcceptError::from_err)?;
            send.finish().map_err(AcceptError::from_err)?;
            debug_println!(
                "{:?}: Sent handshake response after {:?} ({} bytes)",
                remote,
                accept_started_at.elapsed(),
                resp_bytes.len()
            );

            match &response {
                HandshakeResponse::Accept(accept) => {
                    debug_println!(
                        "{:?}: Accepted with active rollover={}, offset={} (total incoming handshake {:?})",
                        remote,
                        accept.rollover.preferred,
                        accept.offset.preferred,
                        accept_started_at.elapsed()
                    );
                    if config_changed {
                        if let Some(ref tx) = handshake_succ_tx {
                            let _ = tx.send((accept.rollover.preferred, accept.offset.preferred));
                        }
                    }
                    self.discovery_cancel.cancel(); // Cancel discovery on successful incoming connection
                    Ok(conn)
                }
                HandshakeResponse::Reject(_) => {
                    conn.close(1u32.into(), b"handshake rejected");
                    Err(AcceptError::from_err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "handshake rejected",
                    )))
                }
            }
        }
    }

    fn accept(&self, conn: Connection) -> impl Future<Output = Result<(), AcceptError>> + Send {
        let gossip = self.gossip.clone();
        let peer_connected_tx = self.peer_connected_tx.clone();
        async move {
            gossip.accept(conn).await?;
            let _ = peer_connected_tx.send(true);
            Ok(())
        }
    }
}

// Initiates handshake with peer, returns connection and parameters
pub async fn perform_handshake(
    endpoint: &iroh::Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
    state: Arc<Mutex<HandshakeState>>,
    slp_version: [u8; 3],
    ssp_version: [u8; 3],
) -> Result<iroh::endpoint::Connection, String> {
    let peer_addr: iroh::EndpointAddr = peer.into();
    let peer_id = peer_addr.id;
    let handshake_started_at = tokio::time::Instant::now();
    debug_println!("{:?}: Initiating handshake...", peer_id);

    let conn = endpoint
        .connect(peer_addr, SSP_ALPN)
        .await
        .map_err(|e| format!("handshake connect failed: {e}"))?;
    debug_println!(
        "{:?}: Endpoint connect completed after {:?}",
        peer_id,
        handshake_started_at.elapsed()
    );

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("handshake open_bi failed: {e}"))?;
    debug_println!(
        "{:?}: Opened handshake bi stream after {:?}",
        peer_id,
        handshake_started_at.elapsed()
    );

    // Send our offer
    let mut hs = state.lock().await;
    let offer = HandshakeOffer {
        config: hs.config,
        slp_version,
        ssp_version,
    };
    let offer_bytes = serde_json::to_vec(&offer).map_err(|e| format!("serialize offer: {e}"))?;
    send.write_all(&offer_bytes)
        .await
        .map_err(|e| format!("handshake send failed: {e}"))?;
    send.finish()
        .map_err(|e| format!("handshake finish failed: {e}"))?;

    debug_println!(
        "{:?}: Was sent our handshake offer after {:?} ({} bytes)",
        peer_id,
        handshake_started_at.elapsed(),
        offer_bytes.len()
    );

    // Read response to offer
    let resp_bytes = recv
        .read_to_end(MAX_HANDSHAKE_MSG)
        .await
        .map_err(|e| format!("handshake read failed: {e}"))?;
    debug_println!(
        "{:?}: Read handshake response after {:?} ({} bytes)",
        peer_id,
        handshake_started_at.elapsed(),
        resp_bytes.len()
    );

    let response: HandshakeResponse =
        serde_json::from_slice(&resp_bytes).map_err(|e| format!("parse response: {e}"))?;

    match response {
        HandshakeResponse::Accept(accept) => {
            debug_println!(
                "{:?}: Accepted handshake for rollover={}, offset={} (total outgoing handshake {:?})",
                peer_id,
                accept.rollover.preferred,
                accept.offset.preferred,
                handshake_started_at.elapsed()
            );
            if !accept_is_valid(hs.config, &accept) {
                return Err("Peer returned invalid connection configuration".to_string());
            }
            // Narrow parameters, should be contained by our config but intersect for bad response
            hs.config.rollover =
                accept
                    .rollover
                    .intersect(&hs.config.rollover)
                    .ok_or_else(|| {
                        format!(
                            "rollover range [{}, {}] does not overlap group window [{}, {}]",
                            offer.config.rollover.min,
                            offer.config.rollover.max,
                            hs.config.rollover.min,
                            hs.config.rollover.max,
                        )
                    })?;
            hs.config.offset = accept.offset.intersect(&hs.config.offset).ok_or_else(|| {
                format!(
                    "offset range [{}, {}] does not overlap group window [{}, {}]",
                    offer.config.offset.min,
                    offer.config.offset.max,
                    hs.config.offset.min,
                    hs.config.offset.max,
                )
            })?;

            Ok(conn)
        }
        HandshakeResponse::Reject(reject) => {
            debug_println!("{:?}: Rejected our handshake: {}", peer_id, reject.reason);
            Err(reject.reason)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn handshake_offer_ignores_unknown_fields() {
        let offer: HandshakeOffer = serde_json::from_value(json!({
            "config": {
                "rollover": {
                    "min": 60,
                    "preferred": 120,
                    "max": 240,
                    "future_rollover_field": { "ignored": true }
                },
                "offset": {
                    "min": 30,
                    "preferred": 60,
                    "max": 120,
                    "future_offset_field": [1, 2, 3]
                },
                "slp_version_min": [0, 0, 0],
                "slp_version_max": [255, 255, 255],
                "ssp_version_min": [0, 0, 0],
                "ssp_version_max": [255, 255, 255],
                "future_config_field": "ignored"
            },
            "slp_version": [3, 19, 0],
            "ssp_version": [0, 1, 0],
            "future_offer_field": {
                "nested": "ignored"
            }
        }))
        .unwrap();

        assert_eq!(offer.config.rollover.preferred, 120);
        assert_eq!(offer.config.offset.preferred, 60);
        assert_eq!(offer.config.ssp_version_min, [0, 0, 0]);
        assert_eq!(offer.config.ssp_version_max, [255, 255, 255]);
        assert_eq!(offer.slp_version, [3, 19, 0]);
        assert_eq!(offer.ssp_version, [0, 1, 0]);
    }

    #[test]
    fn handshake_response_accept_ignores_unknown_fields() {
        let response: HandshakeResponse = serde_json::from_value(json!({
            "Accept": {
                "rollover": {
                    "min": 60,
                    "preferred": 120,
                    "max": 240,
                    "future_rollover_field": "ignored"
                },
                "offset": {
                    "min": 30,
                    "preferred": 60,
                    "max": 120,
                    "future_offset_field": { "ignored": true }
                },
                "future_accept_field": ["ignored"]
            }
        }))
        .unwrap();

        match response {
            HandshakeResponse::Accept(accept) => {
                assert_eq!(accept.rollover.preferred, 120);
                assert_eq!(accept.offset.preferred, 60);
            }
            HandshakeResponse::Reject(_) => panic!("expected accept"),
        }
    }
}
