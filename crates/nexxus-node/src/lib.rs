//! Лабораторный узел: сейф, до трёх копий, проверка чанка и льгота.
//! Оплаты и Tor здесь нет.

mod account;

pub use account::{load_account, Account};

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use nexxus_crypto::{parse_contact, Identity};
use nexxus_net::Mesh;
use nexxus_vault::{audit_proof, Holder, Store};
use serde_json::{json, Value};

const PENALTY_MS: u64 = 30 * 24 * 60 * 60 * 1000;

struct Core {
    mesh: Mesh,
    store: Mutex<Store>,
    acks: Mutex<HashMap<String, mpsc::Sender<bool>>>,
    audits: Mutex<HashMap<String, mpsc::Sender<String>>>,
    blocked_until: Mutex<HashMap<String, u64>>,
}

#[derive(Clone)]
pub struct Node {
    core: Arc<Core>,
}

impl Node {
    pub fn start(dir: &std::path::Path, identity: Identity, device_id: [u8; 16], name: &str, port: u16) -> std::io::Result<Self> {
        let mesh = Mesh::listen(identity.clone(), name, "127.0.0.1", port)?;
        let store = if dir.join("map.bin").is_file() {
            Store::open(dir, identity, device_id)
        } else {
            Store::create(dir, identity, device_id)
        }
        .map_err(|e| std::io::Error::other(e.0))?;
        let node = Self {
            core: Arc::new(Core {
                mesh,
                store: Mutex::new(store),
                acks: Mutex::new(HashMap::new()),
                audits: Mutex::new(HashMap::new()),
                blocked_until: Mutex::new(HashMap::new()),
            }),
        };
        let handler = node.clone();
        node.core.mesh.set_handler(Arc::new(move |fp, obj| handler.on_packet(fp, obj)));
        Ok(node)
    }

    pub fn contact(&self) -> String {
        self.core.mesh.contact()
    }

    pub fn add_file(&self, id: &str, name: &str, bytes: &[u8]) -> Result<(), String> {
        self.core.store.lock().map_err(|_| "замок")?.add_file(id, name, bytes).map(|_| ()).map_err(|e| e.0)
    }

    pub fn copies(&self, id: &str) -> usize {
        self.core
            .store
            .lock()
            .ok()
            .and_then(|store| store.files().ok())
            .and_then(|files| files.into_iter().find(|file| file.id == id))
            .map(|file| file.replicas.len())
            .unwrap_or(0)
    }

    pub fn file_ids(&self) -> Vec<String> {
        self.core
            .store
            .lock()
            .ok()
            .and_then(|store| store.files().ok())
            .map(|files| files.into_iter().map(|file| file.id).collect())
            .unwrap_or_default()
    }

    pub fn dial(&self, uri: &str) -> Result<(), String> {
        self.core.mesh.dial(uri)
    }

    pub fn send_chat(&self, fingerprint: &str, text: &str) -> Result<(), String> {
        self.core.mesh.send_chat(fingerprint, text)
    }

    pub fn wait_peer(&self, fingerprint: &str, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.core.mesh.peers().iter().any(|fp| fp == fingerprint) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        false
    }

    pub fn replicate_to(&self, id: &str, contact_uri: &str) -> Result<(), String> {
        let contact = parse_contact(contact_uri).map_err(|e| e.0)?;
        if !self.core.mesh.peers().iter().any(|fp| fp == &contact.fingerprint) {
            return Err("нет канала".into());
        }
        if self.blocked(&contact.fingerprint) {
            return Err("этой ноде новые чанки не кладём".into());
        }
        let planned = {
            let store = self.core.store.lock().map_err(|_| "замок")?;
            let files = store.files().map_err(|e| e.0)?;
            let file = files.iter().find(|item| item.id == id).ok_or("Файл не найден.")?;
            if file.replicas.len() >= 3 || file.replicas.iter().any(|replica| replica.holder == contact.fingerprint) {
                return Ok(());
            }
            let taken: Vec<u64> = file.replicas.iter().map(|replica| replica.slot).collect();
            let slot = (1..=3).find(|slot| !taken.contains(slot)).ok_or("нет свободного слота")?;
            store.plan_replica(id, slot).map_err(|e| e.0)?
        };
        for (cid, body) in planned.cids.iter().zip(&planned.bodies) {
            let (tx, rx) = mpsc::channel();
            self.core.acks.lock().map_err(|_| "замок")?.insert(cid.clone(), tx);
            self.core.mesh.send_json(
                &contact.fingerprint,
                &json!({"t": "blob_put", "cid": cid, "data": b64(body)}),
            )?;
            if rx.recv_timeout(Duration::from_secs(8)).ok() != Some(true) {
                return Err(format!("копия не подтвердилась: {cid}"));
            }
        }
        let holder = Holder {
            fingerprint: contact.fingerprint,
            host: contact.host,
            port: u64::from(contact.port),
            pub_hex: contact.public_hex,
        };
        self.core
            .store
            .lock()
            .map_err(|_| "замок")?
            .pin_replica(id, &planned, &holder, now_ms())
            .map_err(|e| e.0)
    }

    pub fn audit_holder(&self, id: &str) -> Result<bool, String> {
        let (holder, cid, slot, index, expected) = {
            let store = self.core.store.lock().map_err(|_| "замок")?;
            let file = store.files().map_err(|e| e.0)?.into_iter().find(|file| file.id == id).ok_or("Файл не найден.")?;
            let replica = file.replicas.first().ok_or("копии нет")?.clone();
            let index = 0usize;
            let challenge = rand32();
            let expected = store.proof_for(id, replica.slot, index, &challenge).map_err(|e| e.0)?;
            (replica.holder, replica.cids[index].clone(), replica.slot, challenge, expected)
        };
        let challenge_hex = hex::encode(index);
        let key = format!("{cid}:{challenge_hex}");
        let (tx, rx) = mpsc::channel();
        self.core.audits.lock().map_err(|_| "замок")?.insert(key, tx);
        self.core.mesh.send_json(&holder, &json!({"t": "audit", "cid": cid, "challenge": challenge_hex}))?;
        let verdict = rx.recv_timeout(Duration::from_secs(4)).unwrap_or_else(|_| "timeout".into());
        let bad = verdict == "miss" || (verdict != "timeout" && verdict != expected);
        let mut store = self.core.store.lock().map_err(|_| "замок")?;
        if !bad {
            store.note_seen(id, slot, now_ms()).map_err(|e| e.0)?;
            return Ok(true);
        }
        store.unpin_replica(id, slot, now_ms()).map_err(|e| e.0)?;
        self.note_fail(&holder);
        Ok(false)
    }

    pub fn expire(&self, grace_ms: u64) -> Result<usize, String> {
        let now = now_ms();
        let stale = self.core.store.lock().map_err(|_| "замок")?.stale_replicas(grace_ms, now).map_err(|e| e.0)?;
        for (id, slot, holder) in &stale {
            self.core.store.lock().map_err(|_| "замок")?.unpin_replica(id, *slot, now).map_err(|e| e.0)?;
            self.note_fail(holder);
        }
        Ok(stale.len())
    }

    fn blocked(&self, fingerprint: &str) -> bool {
        self.core
            .blocked_until
            .lock()
            .ok()
            .and_then(|map| map.get(fingerprint).copied())
            .map(|until| until > now_ms())
            .unwrap_or(false)
    }

    fn note_fail(&self, fingerprint: &str) {
        if let Ok(mut map) = self.core.blocked_until.lock() {
            map.insert(fingerprint.to_string(), now_ms().saturating_add(PENALTY_MS));
        }
    }

    fn on_packet(&self, fp: &str, obj: Value) {
        match obj["t"].as_str() {
            Some("blob_put") => {
                let Some(cid) = obj["cid"].as_str() else { return };
                let Some(data) = obj["data"].as_str() else { return };
                if data.len() > 80_000 {
                    return;
                }
                let Ok(ct) = base64::engine::general_purpose::STANDARD.decode(data) else { return };
                let Ok(store) = self.core.store.lock() else { return };
                if store.store_foreign(cid, &ct).ok() == Some(true) {
                    drop(store);
                    let _ = self.core.mesh.send_json(fp, &json!({"t": "blob_ack", "cid": cid}));
                }
            }
            Some("blob_ack") => {
                if let Some(cid) = obj["cid"].as_str() {
                    if let Some(tx) = self.core.acks.lock().ok().and_then(|mut acks| acks.remove(cid)) {
                        let _ = tx.send(true);
                    }
                }
            }
            Some("blob_get") => {
                let Some(cid) = obj["cid"].as_str() else { return };
                let found = self.core.store.lock().ok().and_then(|store| store.foreign_cipher(cid));
                let message = if let Some(ct) = found {
                    json!({"t": "blob_data", "cid": cid, "data": b64(&ct)})
                } else {
                    json!({"t": "blob_miss", "cid": cid})
                };
                let _ = self.core.mesh.send_json(fp, &message);
            }
            Some("audit") => {
                let Some(cid) = obj["cid"].as_str() else { return };
                let Some(challenge) = obj["challenge"].as_str() else { return };
                if challenge.len() != 64 {
                    return;
                }
                let Ok(raw) = hex::decode(challenge) else { return };
                let ct = self.core.store.lock().ok().and_then(|store| store.foreign_cipher(cid));
                let message = if let Some(ct) = ct {
                    json!({"t": "audit_ok", "cid": cid, "challenge": challenge, "proof": audit_proof(&ct, &raw)})
                } else {
                    json!({"t": "audit_miss", "cid": cid, "challenge": challenge})
                };
                let _ = self.core.mesh.send_json(fp, &message);
            }
            Some("audit_ok") | Some("audit_miss") => {
                let key = format!("{}:{}", obj["cid"].as_str().unwrap_or(""), obj["challenge"].as_str().unwrap_or(""));
                if let Some(tx) = self.core.audits.lock().ok().and_then(|mut audits| audits.remove(&key)) {
                    let verdict = if obj["t"] == "audit_miss" {
                        "miss".to_string()
                    } else {
                        obj["proof"].as_str().unwrap_or("").to_string()
                    };
                    let _ = tx.send(verdict);
                }
            }
            Some("ping") => {
                let _ = self.core.mesh.send_json(fp, &json!({"t": "pong", "ts": now_ms()}));
            }
            _ => {}
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn rand32() -> [u8; 32] {
    let mut raw = [0u8; 32];
    let _ = getrandom::getrandom(&mut raw);
    raw
}
