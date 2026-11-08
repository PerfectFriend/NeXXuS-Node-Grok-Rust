//! Лабораторный узел: сейф, до трёх копий, проверка чанка и льгота.
//! Оплаты и Tor здесь нет.

mod account;

pub use account::{load_account, Account};

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use nexxus_crypto::{parse_contact, Identity};
use nexxus_net::Mesh;
use nexxus_vault::{audit_proof, Holder, Store};
use nexxus_wire::{create_queue_key, open_queue, pack_xftp, sign_miner, unpack_xftp, verify_desc, verify_miner, Sealed};
use sha2::{Digest, Sha256};
use serde_json::{json, Value};

const PENALTY_MS: u64 = 30 * 24 * 60 * 60 * 1000;

struct Core {
    mesh: Mesh,
    store: Mutex<Store>,
    acks: Mutex<HashMap<String, mpsc::Sender<bool>>>,
    audits: Mutex<HashMap<String, mpsc::Sender<String>>>,
    blocked_until: Mutex<HashMap<String, u64>>,
    identity: Identity,
    dir: std::path::PathBuf,
    queues: Mutex<HashMap<String, Queue>>,
    pending_open: Mutex<HashMap<String, mpsc::Sender<String>>>,
    pending_pull: Mutex<HashMap<String, mpsc::Sender<Vec<Value>>>>,
    miner: Mutex<bool>,
    miners: Mutex<HashMap<String, u64>>,
}

struct Queue {
    pub_hex: String,
    owner: String,
    msgs: Vec<Value>,
}

pub struct Inbox {
    pub id: String,
    pub host: String,
    pub priv_key: [u8; 32],
    pub pub_hex: String,
}

#[derive(Clone)]
pub struct Node {
    core: Arc<Core>,
}

impl Node {
    pub fn start(dir: &std::path::Path, identity: Identity, device_id: [u8; 16], name: &str, port: u16) -> std::io::Result<Self> {
        Self::start_with(dir, identity, device_id, name, port, "127.0.0.1", "127.0.0.1", "lab", None)
    }

    pub fn start_with(
        dir: &std::path::Path,
        identity: Identity,
        device_id: [u8; 16],
        name: &str,
        port: u16,
        bind_host: &str,
        advertise: &str,
        profile: &str,
        socks: Option<(&str, u16)>,
    ) -> std::io::Result<Self> {
        let mesh = Mesh::listen_on(bind_host, identity.clone(), name, advertise, port)?;
        mesh.set_route(profile, socks).map_err(|e| std::io::Error::other(e))?;
        let store = if dir.join("map.bin").is_file() {
            Store::open(dir, identity.clone(), device_id)
        } else {
            Store::create(dir, identity.clone(), device_id)
        }
        .map_err(|e| std::io::Error::other(e.0))?;
        let node = Self {
            core: Arc::new(Core {
                mesh,
                store: Mutex::new(store),
                acks: Mutex::new(HashMap::new()),
                audits: Mutex::new(HashMap::new()),
                blocked_until: Mutex::new(HashMap::new()),
                identity,
                dir: dir.to_path_buf(),
                queues: Mutex::new(load_queues(dir)),
                pending_open: Mutex::new(HashMap::new()),
                pending_pull: Mutex::new(HashMap::new()),
                miner: Mutex::new(false),
                miners: Mutex::new(HashMap::new()),
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

    pub fn chats(&self) -> Vec<(String, String)> {
        self.core.mesh.chats().into_iter().map(|line| (line.from, line.text)).collect()
    }

    pub fn command(&self, line: &str) -> String {
        let line = line.trim();
        let (verb, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let rest = rest.trim();
        match verb {
            "status" | "" => {
                let peers = self.core.mesh.peers().join(",");
                format!(
                    "ok contact={} files={} peers={}",
                    self.contact(),
                    self.file_ids().len(),
                    if peers.is_empty() { "-".into() } else { peers }
                )
            }
            "contact" => self.contact(),
            "peers" => {
                let peers = self.core.mesh.peers();
                if peers.is_empty() { "ok -".into() } else { format!("ok {}", peers.join(" ")) }
            }
            "files" => {
                let lines: Vec<String> = self
                    .file_ids()
                    .into_iter()
                    .map(|id| format!("{id} copies={}", self.copies(&id)))
                    .collect();
                if lines.is_empty() { "ok -".into() } else { format!("ok {}", lines.join(" | ")) }
            }
            "chats" => {
                let lines: Vec<String> = self.chats().into_iter().map(|(from, text)| format!("{from} {text}")).collect();
                if lines.is_empty() { "ok -".into() } else { format!("ok {}", lines.join(" | ")) }
            }
            "dial" => match self.dial(rest) {
                Ok(()) => "ok dial".into(),
                Err(err) => format!("err {err}"),
            },
            "put" => self.cmd_put(rest),
            "chat" => {
                let Some((fp, text)) = rest.split_once(char::is_whitespace) else {
                    return "err нужно: chat ОТПЕЧАТОК текст".into();
                };
                match self.send_chat(fp, text.trim()) {
                    Ok(()) => "ok chat".into(),
                    Err(err) => format!("err {err}"),
                }
            }
            "sync" => match self.sync_drive() {
                Ok(()) => "ok drive".into(),
                Err(err) => format!("err {err}"),
            },
            _ => "err команда: status, contact, peers, files, chats, dial, put, chat, sync".into(),
        }
    }

    pub fn serve_control(&self, port: u16) -> std::io::Result<u16> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        let bound = listener.local_addr()?.port();
        let node = self.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                let node = node.clone();
                std::thread::spawn(move || {
                    let _ = answer_control(&node, stream);
                });
            }
        });
        Ok(bound)
    }

    fn cmd_put(&self, path: &str) -> String {
        if path.is_empty() {
            return "err нужно: put ПУТЬ".into();
        }
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => return format!("err {err}"),
        };
        if bytes.len() > 64 * 1024 * 1024 {
            return "err файл больше 64 МБ".into();
        }
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file.bin");
        let id = format!("{}-{}", sanitize(name), now_ms());
        match self.add_file(&id, name, &bytes) {
            Ok(()) => format!("ok {id}"),
            Err(err) => format!("err {err}"),
        }
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
        if self.core.miner.lock().map(|flag| *flag).unwrap_or(false) {
            return Ok(());
        }
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

    pub fn enable_miner(&self) {
        if let Ok(mut flag) = self.core.miner.lock() {
            *flag = true;
        }
        let node = self.clone();
        self.core.mesh.set_on_up(std::sync::Arc::new(move |fp| node.announce_miner(fp)));
        for fp in self.core.mesh.peers() {
            self.announce_miner(&fp);
        }
    }

    pub fn miner_supply(&self, fingerprint: &str) -> Option<u64> {
        self.core.miners.lock().ok().and_then(|map| map.get(fingerprint).copied())
    }

    pub fn named_files(&self) -> Vec<(String, String, usize)> {
        self.core
            .store
            .lock()
            .ok()
            .and_then(|store| store.files().ok())
            .map(|files| files.into_iter().map(|file| (file.id, file.name, file.replicas.len())).collect())
            .unwrap_or_default()
    }

    pub fn store_bytes(&self, name: &str, bytes: &[u8]) -> Result<String, String> {
        let id = format!("{}-{}", sanitize(name), now_ms());
        self.core.store.lock().map_err(|_| "замок")?.add_file(&id, name, bytes).map_err(|e| e.0)?;
        Ok(id)
    }

    pub fn read_bytes(&self, id: &str) -> Result<Vec<u8>, String> {
        self.core.store.lock().map_err(|_| "замок")?.read_file(id).map_err(|e| e.0)
    }

    pub fn open_inbox(&self, host_fp: &str) -> Result<Inbox, String> {
        let key = create_queue_key()?;
        let (tx, rx) = mpsc::channel();
        self.core.pending_open.lock().map_err(|_| "замок")?.insert(key.pub_hex.clone(), tx);
        if let Err(err) = self.core.mesh.send_json(host_fp, &json!({"t": "smp_open", "pub": key.pub_hex})) {
            self.core.pending_open.lock().ok().map(|mut pending| pending.remove(&key.pub_hex));
            return Err(err);
        }
        let id = match rx.recv_timeout(Duration::from_secs(4)) {
            Ok(id) => id,
            Err(_) => {
                self.core.pending_open.lock().ok().map(|mut pending| pending.remove(&key.pub_hex));
                return Err("Очередь SMP не открылась.".into());
            }
        };
        Ok(Inbox { id, host: host_fp.to_string(), priv_key: key.priv_key, pub_hex: key.pub_hex })
    }

    pub fn send_sealed(&self, host_fp: &str, id: &str, recipient_pub: &[u8; 32], plain: &[u8]) -> Result<(), String> {
        let sealed = nexxus_wire::seal_queue(recipient_pub, plain)?;
        self.core.mesh.send_json(host_fp, &json!({
            "t": "smp_send",
            "id": id,
            "eph": sealed.eph,
            "nonce": sealed.nonce,
            "ct": sealed.ct,
        }))
    }

    pub fn pull_sealed(&self, host_fp: &str, id: &str, recipient_priv: &[u8; 32]) -> Result<Vec<Vec<u8>>, String> {
        let (tx, rx) = mpsc::channel();
        self.core.pending_pull.lock().map_err(|_| "замок")?.insert(id.to_string(), tx);
        if let Err(err) = self.core.mesh.send_json(host_fp, &json!({"t": "smp_pull", "id": id})) {
            self.core.pending_pull.lock().ok().map(|mut pending| pending.remove(id));
            return Err(err);
        }
        let msgs = match rx.recv_timeout(Duration::from_secs(4)) {
            Ok(msgs) => msgs,
            Err(_) => {
                self.core.pending_pull.lock().ok().map(|mut pending| pending.remove(id));
                return Err("Очередь SMP не ответила.".into());
            }
        };
        msgs.iter()
            .map(|message| {
                open_queue(
                    recipient_priv,
                    &Sealed {
                        eph: message["eph"].as_str().unwrap_or("").into(),
                        nonce: message["nonce"].as_str().unwrap_or("").into(),
                        ct: message["ct"].as_str().unwrap_or("").into(),
                    },
                )
            })
            .collect()
    }

    pub fn queue_record(&self, id: &str) -> Option<(String, String)> {
        let queues = self.core.queues.lock().ok()?;
        let queue = queues.get(id)?;
        let dumped = serde_json::to_string(&queue.msgs).unwrap_or_default();
        Some((queue.owner.clone(), dumped))
    }

    pub fn xftp_send(&self, fingerprint: &str, name: &str, bytes: &[u8]) -> Result<Value, String> {
        let (desc, bodies) = pack_xftp(name, bytes, &self.core.identity)?;
        if desc.get("host").is_some() || desc.get("port").is_some() {
            return Err("в описании XFTP не должно быть адреса".into());
        }
        let cids = desc["cids"].as_array().ok_or("описание XFTP не сошлось")?;
        for (cid, body) in cids.iter().zip(&bodies) {
            let cid = cid.as_str().unwrap_or("");
            let (tx, rx) = mpsc::channel();
            self.core.acks.lock().map_err(|_| "замок")?.insert(cid.to_string(), tx);
            self.core.mesh.send_json(fingerprint, &json!({"t": "blob_put", "cid": cid, "data": b64(body)}))?;
            if rx.recv_timeout(Duration::from_secs(8)).ok() != Some(true) {
                return Err(format!("чанки XFTP не подтвердились: {cid}"));
            }
        }
        self.core.mesh.send_json(fingerprint, &json!({"t": "xftp_desc", "desc": desc.clone()}))?;
        Ok(desc)
    }

    pub fn sync_drive(&self) -> Result<(), String> {
        let drive = self.core.dir.join("drive");
        std::fs::create_dir_all(&drive).map_err(|e| e.to_string())?;
        let index_path = self.core.dir.join("drive-index.json");
        let mut index = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        let mut store = self.core.store.lock().map_err(|_| "замок")?;
        let files = store.files().map_err(|e| e.0)?;
        let live: std::collections::HashSet<String> = files.iter().map(|file| file.id.clone()).collect();
        let stale: Vec<String> = index
            .iter()
            .filter_map(|(name, meta)| {
                let id = meta["id"].as_str().unwrap_or("");
                if live.contains(id) { None } else { Some(name.clone()) }
            })
            .collect();
        for name in stale {
            let _ = std::fs::remove_file(drive.join(&name));
            index.remove(&name);
        }
        for rec in &files {
            let known = index.iter().find(|(_, meta)| meta["id"].as_str() == Some(rec.id.as_str())).map(|(name, _)| name.clone());
            let mut name = if let Some(name) = known.clone() { name } else { safe_drive_name(&rec.name) };
            if known.is_none() && index.contains_key(&name) {
                name = format!("{}-{name}", &rec.id[..rec.id.len().min(8)]);
            }
            let dest = drive.join(&name);
            let indexed = index.get(&name).and_then(|meta| meta["id"].as_str()) == Some(rec.id.as_str());
            if indexed && !dest.exists() {
                store.drop_file(&rec.id).map_err(|e| e.0)?;
                index.remove(&name);
                continue;
            }
            if dest.is_file() {
                let disk = std::fs::read(&dest).map_err(|e| e.to_string())?;
                let hash = hex::encode(Sha256::digest(&disk));
                if hash == rec.hash {
                    index.insert(name, json!({"id": rec.id, "hash": rec.hash}));
                    continue;
                }
                if indexed {
                    store.drop_file(&rec.id).map_err(|e| e.0)?;
                    let id = format!("{}-{}", sanitize(&name), now_ms());
                    let stored = store.add_file(&id, &rec.name, &disk).map_err(|e| e.0)?;
                    index.insert(name, json!({"id": stored.id, "hash": stored.hash}));
                    continue;
                }
            }
            let bytes = store.read_file(&rec.id).map_err(|e| e.0)?;
            std::fs::write(&dest, &bytes).map_err(|e| e.to_string())?;
            index.insert(name, json!({"id": rec.id, "hash": rec.hash}));
        }
        let names: Vec<String> = std::fs::read_dir(&drive).map_err(|e| e.to_string())?.filter_map(|item| item.ok()?.file_name().into_string().ok()).collect();
        for name in names {
            if name.starts_with('.') || index.contains_key(&name) {
                continue;
            }
            let full = drive.join(&name);
            if !full.is_file() {
                continue;
            }
            let bytes = std::fs::read(&full).map_err(|e| e.to_string())?;
            let id = format!("{}-{}", sanitize(&name), now_ms());
            let stored = store.add_file(&id, &name, &bytes).map_err(|e| e.0)?;
            index.insert(name, json!({"id": stored.id, "hash": stored.hash}));
        }
        std::fs::write(index_path, serde_json::to_vec_pretty(&Value::Object(index)).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn announce_miner(&self, fingerprint: &str) {
        if !self.core.miner.lock().map(|flag| *flag).unwrap_or(false) {
            return;
        }
        let supply = 64 * 1024 * 1024u64;
        let sig = sign_miner(&self.core.identity, supply);
        let _ = self.core.mesh.send_json(fingerprint, &json!({"t": "miner_ad", "supply": supply, "sig": sig}));
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
            Some("miner_ad") => self.accept_miner(fp, &obj),
            Some("smp_open") => self.accept_queue_open(fp, &obj),
            Some("smp_opened") => {
                let Some(pub_hex) = obj["pub"].as_str() else { return };
                let Some(id) = obj["id"].as_str() else { return };
                if let Some(tx) = self.core.pending_open.lock().ok().and_then(|mut pending| pending.remove(pub_hex)) {
                    let _ = tx.send(id.to_string());
                }
            }
            Some("smp_send") => self.accept_queue_send(&obj),
            Some("smp_pull") => self.accept_queue_pull(fp, &obj),
            Some("smp_msgs") => {
                let Some(id) = obj["id"].as_str() else { return };
                let Some(msgs) = obj["msgs"].as_array() else { return };
                if let Some(tx) = self.core.pending_pull.lock().ok().and_then(|mut pending| pending.remove(id)) {
                    let _ = tx.send(msgs.clone());
                }
            }
            Some("xftp_desc") => self.accept_xftp(&obj["desc"]),
            _ => {}
        }
    }

    fn accept_miner(&self, fp: &str, obj: &Value) {
        let (Some(supply), Some(sig)) = (obj["supply"].as_u64(), obj["sig"].as_str()) else { return };
        let Some(ed) = self.core.mesh.peer_ed(fp) else { return };
        if !verify_miner(fp, &ed, supply, sig) {
            return;
        }
        if let Ok(mut miners) = self.core.miners.lock() {
            miners.insert(fp.to_string(), supply);
        }
    }

    fn accept_queue_open(&self, fp: &str, obj: &Value) {
        let Some(pub_hex) = obj["pub"].as_str() else { return };
        if pub_hex.len() != 64 || !pub_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return;
        }
        let id = hex::encode(rand16());
        {
            let Ok(mut queues) = self.core.queues.lock() else { return };
            queues.insert(id.clone(), Queue { pub_hex: pub_hex.to_string(), owner: fp.to_string(), msgs: Vec::new() });
            save_queues(&self.core.dir, &queues);
        }
        let _ = self.core.mesh.send_json(fp, &json!({"t": "smp_opened", "id": id, "pub": pub_hex}));
    }

    fn accept_queue_send(&self, obj: &Value) {
        let Some(id) = obj["id"].as_str() else { return };
        let (Some(eph), Some(nonce), Some(ct)) = (obj["eph"].as_str(), obj["nonce"].as_str(), obj["ct"].as_str()) else {
            return;
        };
        if ct.len() > 100_000 {
            return;
        }
        let Ok(mut queues) = self.core.queues.lock() else { return };
        let Some(queue) = queues.get_mut(id) else { return };
        if queue.msgs.len() >= 32 {
            return;
        }
        queue.msgs.push(json!({"eph": eph, "nonce": nonce, "ct": ct}));
        save_queues(&self.core.dir, &queues);
    }

    fn accept_queue_pull(&self, fp: &str, obj: &Value) {
        let Some(id) = obj["id"].as_str() else { return };
        let msgs = {
            let Ok(mut queues) = self.core.queues.lock() else { return };
            let Some(queue) = queues.get_mut(id) else { return };
            if queue.owner != fp {
                return;
            }
            let msgs = std::mem::take(&mut queue.msgs);
            save_queues(&self.core.dir, &queues);
            msgs
        };
        if self.core.mesh.send_json(fp, &json!({"t": "smp_msgs", "id": id, "msgs": msgs.clone()})).is_err() {
            if let Ok(mut queues) = self.core.queues.lock() {
                if let Some(queue) = queues.get_mut(id) {
                    for message in msgs.into_iter().rev() {
                        queue.msgs.insert(0, message);
                    }
                    save_queues(&self.core.dir, &queues);
                }
            }
        }
    }

    fn accept_xftp(&self, desc: &Value) {
        if !verify_desc(desc) {
            return;
        }
        let Some(cids) = desc["cids"].as_array() else { return };
        let mut bodies = Vec::new();
        {
            let Ok(store) = self.core.store.lock() else { return };
            for cid in cids {
                let Some(cid) = cid.as_str() else { return };
                let Some(ct) = store.foreign_cipher(cid) else { return };
                bodies.push(ct);
            }
        }
        let Ok(plain) = unpack_xftp(desc, &bodies) else { return };
        let name = safe_drive_name(desc["name"].as_str().unwrap_or("file.bin"));
        let _ = self.store_bytes(&name, &plain);
    }
}

fn load_queues(dir: &std::path::Path) -> HashMap<String, Queue> {
    let Ok(text) = std::fs::read_to_string(dir.join("smp.json")) else {
        return HashMap::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return HashMap::new();
    };
    let Some(map) = value.as_object() else {
        return HashMap::new();
    };
    map.iter()
        .filter_map(|(id, item)| {
            Some((
                id.clone(),
                Queue {
                    pub_hex: item["pub"].as_str()?.to_string(),
                    owner: item["owner"].as_str()?.to_string(),
                    msgs: item["msgs"].as_array().cloned().unwrap_or_default(),
                },
            ))
        })
        .collect()
}

fn save_queues(dir: &std::path::Path, queues: &HashMap<String, Queue>) {
    let mut map = serde_json::Map::new();
    for (id, queue) in queues {
        map.insert(id.clone(), json!({"pub": queue.pub_hex, "owner": queue.owner, "msgs": queue.msgs}));
    }
    let _ = std::fs::write(dir.join("smp.json"), serde_json::to_vec(&Value::Object(map)).unwrap_or_default());
}

fn safe_drive_name(name: &str) -> String {
    let clean: String = name.chars().filter(|ch| *ch != '/' && *ch != '\\' && *ch != '\0').take(180).collect();
    let clean = clean.trim();
    if clean.is_empty() { "file.bin".into() } else { clean.to_string() }
}

fn rand16() -> [u8; 16] {
    let mut raw = [0u8; 16];
    let _ = getrandom::getrandom(&mut raw);
    raw
}

fn answer_control(node: &Node, stream: TcpStream) -> std::io::Result<()> {
    let mut stream = stream;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let answer = node.command(&line);
    stream.write_all(answer.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(())
}

fn sanitize(name: &str) -> String {
    let clean: String = name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' { ch } else { '-' })
        .take(40)
        .collect();
    if clean.is_empty() { "file".into() } else { clean }
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
