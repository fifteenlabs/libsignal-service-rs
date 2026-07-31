//! Serialises Double Ratchet session access, per peer.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use libsignal_protocol::ServiceId;

/// Guards the load → ratchet → store cycle for one peer's sessions.
///
/// libsignal advances the ratchet inside `message_encrypt` / `message_decrypt`
/// and writes the new state back through the `SessionStore` trait, so the read
/// and the write are separate awaits with a yield point between them. Two tasks
/// that interleave there both derive from the same chain state, and the second
/// store discards the first — desynchronising the session permanently. Worse,
/// [`MessageSender::create_encrypted_messages`] reads the resulting
/// `SessionNotFound` as corruption and deletes the session outright.
///
/// Clones share one map, so every [`ServiceCipher`] built for an account — the
/// receive path's and every sender's — serialises against the others. Sends to
/// different peers still run concurrently; only same-peer work waits.
///
/// [`MessageSender::create_encrypted_messages`]: crate::sender::MessageSender
/// [`ServiceCipher`]: crate::cipher::ServiceCipher
#[derive(Clone, Default)]
pub struct SessionLocks {
    // Only ever held to look up or insert an entry, never across an await, so
    // it cannot deadlock against the per-peer lock it hands out.
    peers: Arc<Mutex<HashMap<ServiceId, Arc<tokio::sync::Mutex<()>>>>>,
}

impl SessionLocks {
    /// Wait for exclusive access to `peer`'s session state.
    ///
    /// Entries are never removed: one empty mutex per peer ever contacted costs
    /// less than the bookkeeping needed to drop them without losing a waiter.
    pub async fn lock(
        &self,
        peer: &ServiceId,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let peer_lock = {
            let mut peers = self
                .peers
                .lock()
                // The critical section is a map lookup; a poisoned map would
                // mean an unrelated panic, and refusing to send afterwards is
                // worse than continuing with the state we have.
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(peers.entry(*peer).or_default())
        };
        peer_lock.lock_owned().await
    }
}
