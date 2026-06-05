use crate::dolphin::{GameMeta, InputFrame};
use debug_print::{debug_eprintln, debug_println};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::collections::HashMap;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Clone, Copy, Debug)]
pub struct GameKey {
    pub frames: u64,
    pub key: [u8; 32],
}

#[derive(Clone, Debug)]
pub enum CrypterUpdate {
    Key(GameKey),
    Rotate,
}

#[derive(Debug)]
pub enum CrypterInput {
    Frame(InputFrame),
    Reset(GameMeta),
}

#[derive(Debug, Clone)]
pub struct SLPcryptoSponge {
    pub sponge: Shake256,
    pub frames: u64,
}

impl SLPcryptoSponge {
    // Seed with initial 4-byte game seed
    pub fn new(seed: [u8; 4]) -> Self {
        let mut sponge = Shake256::default();
        sponge.update(&seed);
        Self { sponge, frames: 0 }
    }
}

// Absorbs inputs and emits keys
pub struct SLPcrypter {
    input_rx: UnboundedReceiver<CrypterInput>,
    update_tx: UnboundedSender<CrypterUpdate>,
    sponge: SLPcryptoSponge,
    frame_data: HashMap<i64, Vec<u8>>,
    last_finalized_frame: Option<i64>,
    meta: Option<GameMeta>,
    update_key_per_frames: u64,
    rollback_offset_frames: u64,
    last_key_frame: u64,
    pending_rotate_at: Option<u64>,
    reconfig_rx: Option<UnboundedReceiver<(u64, u64)>>,
}

impl SLPcrypter {
    pub fn new(
        input_rx: UnboundedReceiver<CrypterInput>,
        update_tx: UnboundedSender<CrypterUpdate>,
        update_key_per_frames: u64,
        rollback_offset_frames: u64,
        reconfig_rx: Option<UnboundedReceiver<(u64, u64)>>,
    ) -> SLPcrypter {
        Self {
            input_rx,
            update_tx,
            sponge: SLPcryptoSponge::new([0u8; 4]),
            frame_data: HashMap::new(),
            last_finalized_frame: None,
            meta: None,
            update_key_per_frames,
            rollback_offset_frames,
            last_key_frame: 0,
            pending_rotate_at: None,
            reconfig_rx,
        }
    }

    fn reset(&mut self, meta: GameMeta) {
        let seed = meta.seed.to_be_bytes();
        self.sponge = SLPcryptoSponge::new(seed);
        self.frame_data.clear();
        self.last_finalized_frame = None;
        self.last_key_frame = 0;
        self.pending_rotate_at = None;
        self.meta = Some(meta);

        if let Some(key) = self.derive_current_key() {
            let _ = self.update_tx.send(CrypterUpdate::Key(key));
        }
    }

    pub fn handle_frame(&mut self, frame: InputFrame) {
        if self.meta.is_none() {
            return;
        }

        self.frame_data.insert(frame.frame, frame.data);

        let new_finalized = frame.last_finalized_frame;
        let absorb_from = match self.last_finalized_frame {
            Some(old) => old + 1,
            None => new_finalized,
        };
        if absorb_from <= new_finalized {
            for f in absorb_from..=new_finalized {
                if let Some(data) = self.frame_data.remove(&f) {
                    self.sponge.sponge.update(&data);
                    self.sponge.frames += 1;
                }
                let target_frame = self.last_key_frame + self.update_key_per_frames;
                if self.sponge.frames >= target_frame {
                    if let Some(key) = self.derive_current_key() {
                        let _ = self.update_tx.send(CrypterUpdate::Key(key));
                        self.last_key_frame = self.sponge.frames;
                        self.pending_rotate_at = Some(target_frame + self.rollback_offset_frames);
                    }
                }
                if let Some(rotate_at) = self.pending_rotate_at {
                    if self.sponge.frames == rotate_at {
                        let _ = self.update_tx.send(CrypterUpdate::Rotate);
                        self.pending_rotate_at = None;
                    }
                }
            }
        }
        self.last_finalized_frame = Some(match self.last_finalized_frame {
            Some(old) => new_finalized.max(old),
            None => new_finalized,
        });
    }

    // Derive key from current sponge state
    pub fn derive_current_key(&self) -> Option<GameKey> {
        self.meta.as_ref()?;
        let working = self.sponge.sponge.clone();
        let mut xof = working.finalize_xof();
        let mut key = [0u8; 32];
        xof.read(&mut key);
        Some(GameKey {
            frames: self.sponge.frames,
            key,
        })
    }

    pub async fn start(mut self) {
        loop {
            if let Some(ref mut rx) = self.reconfig_rx {
                while let Ok((new_rollover, new_offset)) = rx.try_recv() {
                    self.update_key_per_frames = new_rollover;
                    self.rollback_offset_frames = new_offset;
                }
            }

            match self.input_rx.try_recv() {
                Ok(input) => match input {
                    CrypterInput::Frame(frame) => {
                        self.handle_frame(frame);
                    }
                    CrypterInput::Reset(meta) => {
                        self.reset(meta);
                    }
                },
                Err(TryRecvError::Empty) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                }
                Err(TryRecvError::Disconnected) => {
                    debug_println!("Crypter input channel disconnected, stopping");
                    break;
                }
            }
        }
    }
}

unsafe impl Send for SLPcrypter {}
