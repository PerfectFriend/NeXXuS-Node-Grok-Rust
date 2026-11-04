//! Журнал сейфа. `map.bin` — это JSON, закрытый ключом сейфа тем же кадром, что Linux 0.10.0.
//! Сети здесь нет: только карта, чанки и проверка подписи.

use std::fs;
use std::path::{Path, PathBuf};

use nexxus_crypto::{ed25519_sign, ed25519_verify, open_packed, seal_packed, Identity};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub struct VaultError(pub String);

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err(text: &str) -> VaultError {
    VaultError(text.to_string())
}

#[derive(Clone)]
pub struct Device {
    pub id: [u8; 16],
    pub ed_priv: [u8; 32],
    pub ed_pub: [u8; 32],
}

pub fn derive_device(seed: &[u8; 64], device_id: &[u8; 16]) -> Device {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(b"nexxus-device"), seed)
        .expand(device_id, &mut out)
        .expect("hkdf device");
    Device {
        id: *device_id,
        ed_priv: out,
        ed_pub: nexxus_crypto::ed25519_public(&out),
    }
}

pub fn canon(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let body = items.iter().map(canon).collect::<Vec<_>>().join(",");
            format!("[{body}]")
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body = keys
                .into_iter()
                .map(|key| format!("{}:{}", serde_json::to_string(key).unwrap(), canon(&map[key])))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        other => serde_json::to_string(other).expect("json"),
    }
}

pub fn replica_nonce(prefix16: &[u8], index: u32, slot: u32) -> Result<[u8; 24], VaultError> {
    if prefix16.len() != 16 {
        return Err(err("префикс nonce должен быть 16 байт"));
    }
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix16);
    nonce[16..20].copy_from_slice(&index.to_be_bytes());
    nonce[20..24].copy_from_slice(&slot.to_be_bytes());
    Ok(nonce)
}

pub fn seal_chunk(file_key: &[u8; 32], padded: &[u8], prefix16: &[u8], index: u32, slot: u32) -> Result<(String, Vec<u8>), VaultError> {
    let nonce = replica_nonce(prefix16, index, slot)?;
    let ct = nexxus_crypto::seal(file_key, &nonce, padded).map_err(|e| err(&e.0))?;
    Ok((hex::encode(Sha256::digest(&ct)), ct))
}

pub fn open_chunk(file_key: &[u8; 32], ct: &[u8], prefix_hex: &str, index: u32, slot: u32) -> Result<Vec<u8>, VaultError> {
    let prefix = hex::decode(prefix_hex).map_err(|_| err("префикс"))?;
    let nonce = replica_nonce(&prefix, index, slot)?;
    let plain_and_tag_nonce = {
        let mut packed = nonce.to_vec();
        packed.extend_from_slice(ct);
        open_packed(file_key, &packed).map_err(|e| err(&e.0))?
    };
    Ok(plain_and_tag_nonce)
}

pub fn pad_chunk(slice: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; CHUNK_BYTES];
    let take = slice.len().min(CHUNK_BYTES);
    out[..take].copy_from_slice(&slice[..take]);
    out
}

fn cert_message(device_pub: &[u8]) -> Vec<u8> {
    let mut msg = b"nexxus-device-cert-v1|".to_vec();
    msg.extend_from_slice(device_pub);
    msg
}

fn op_message(op: &Value) -> Vec<u8> {
    format!("nexxus-map-op-v1|{}", canon(op)).into_bytes()
}

fn sign_op(mut op: Map<String, Value>, device: &Device) -> Value {
    op.remove("sig");
    let body = Value::Object(op);
    let sig = hex::encode(ed25519_sign(&device.ed_priv, &op_message(&body)));
    let mut map = body.as_object().unwrap().clone();
    map.insert("sig".into(), Value::String(sig));
    Value::Object(map)
}

fn verify_sig(public: &[u8; 32], op: &Value) -> bool {
    let Some(sig_hex) = op.get("sig").and_then(|v| v.as_str()) else {
        return false;
    };
    let Ok(sig) = decode64(sig_hex) else {
        return false;
    };
    let mut body = op.clone();
    body.as_object_mut().map(|map| map.remove("sig"));
    ed25519_verify(public, &op_message(&body), &sig)
}

pub fn load_journal(packed: &[u8], vault_key: &[u8; 32]) -> Result<Value, VaultError> {
    let plain = open_packed(vault_key, packed).map_err(|_| err("журнал не открывается этим ключом"))?;
    let journal: Value = serde_json::from_slice(&plain).map_err(|_| err("журнал карты повреждён"))?;
    if journal["v"] != 1 || !journal["ops"].is_array() || !journal["devices"].is_array() {
        return Err(err("журнал карты повреждён"));
    }
    Ok(journal)
}

pub fn save_journal(journal: &Value, vault_key: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
    let plain = serde_json::to_vec(journal).map_err(|_| err("журнал"))?;
    seal_packed(vault_key, &plain).map_err(|e| err(&e.0))
}

pub fn map_locator(vault_key: &[u8]) -> String {
    let mut msg = b"nexxus-map-locator-v1|".to_vec();
    msg.extend_from_slice(vault_key);
    hex::encode(Sha256::digest(msg))
}

pub fn audit_proof(ct: &[u8], challenge: &[u8]) -> String {
    let mut msg = ct.to_vec();
    msg.extend_from_slice(challenge);
    hex::encode(Sha256::digest(msg))
}

#[derive(Clone, Debug)]
pub struct Replica {
    pub slot: u64,
    pub prefix: String,
    pub cids: Vec<String>,
    pub holder: String,
    pub seen: u64,
}

#[derive(Clone, Debug)]
pub struct FileRec {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub file_key: String,
    pub local_prefix: String,
    pub chunks: Vec<String>,
    pub replicas: Vec<Replica>,
}

pub fn fold_journal(journal: &Value, node_ed_pub: &[u8; 32]) -> Result<Vec<FileRec>, VaultError> {
    let mut files: Vec<FileRec> = Vec::new();
    let mut revoked = Vec::new();
    let devices = journal["devices"].as_array().ok_or_else(|| err("журнал"))?;
    for op in journal["ops"].as_array().ok_or_else(|| err("журнал"))? {
        if op["op"] == "revoke" {
            if !verify_sig(node_ed_pub, op) {
                return Err(err("подпись отзыва не сходится"));
            }
            revoked.push(op["dev"].as_str().unwrap_or("").to_string());
            continue;
        }
        let dev = op["dev"].as_str().unwrap_or("");
        if revoked.iter().any(|item| item == dev) {
            continue;
        }
        let device_pub = devices
            .iter()
            .find(|device| device["pub"].as_str() == Some(dev))
            .ok_or_else(|| err("подпись журнала не сходится"))?;
        let pub_bytes = decode32(device_pub["pub"].as_str().unwrap_or(""))?;
        let cert = decode64(device_pub["cert"].as_str().unwrap_or(""))?;
        let cert_ok = ed25519_verify(node_ed_pub, &cert_message(&pub_bytes), &cert);
        if !cert_ok || !verify_sig(&pub_bytes, op) {
            return Err(err("подпись журнала не сходится"));
        }
        apply_op(&mut files, op);
    }
    Ok(files)
}

fn apply_op(files: &mut Vec<FileRec>, op: &Value) {
    let id = op["id"].as_str().unwrap_or("").to_string();
    match op["op"].as_str() {
        Some("add") => {
            files.retain(|file| file.id != id);
            files.push(FileRec {
                id,
                name: op["name"].as_str().unwrap_or("").to_string(),
                size: op["size"].as_u64().unwrap_or(0),
                hash: op["hash"].as_str().unwrap_or("").to_string(),
                file_key: op["fileKey"].as_str().unwrap_or("").to_string(),
                local_prefix: op["localPrefix"].as_str().unwrap_or("").to_string(),
                chunks: strings(op.get("chunks")),
                replicas: Vec::new(),
            });
        }
        Some("pin") => {
            let Some(file) = files.iter_mut().find(|file| file.id == id) else {
                return;
            };
            let slot = op["slot"].as_u64().unwrap_or(0);
            file.replicas.retain(|replica| replica.slot != slot);
            file.replicas.push(Replica {
                slot,
                prefix: op["prefix"].as_str().unwrap_or("").to_string(),
                cids: strings(op.get("cids")),
                holder: op["holder"].as_str().unwrap_or("").to_string(),
                seen: op["at"].as_u64().unwrap_or(0),
            });
        }
        Some("seen") => {
            let Some(file) = files.iter_mut().find(|file| file.id == id) else {
                return;
            };
            let slot = op["slot"].as_u64().unwrap_or(0);
            if let Some(replica) = file.replicas.iter_mut().find(|replica| replica.slot == slot) {
                replica.seen = op["at"].as_u64().unwrap_or(replica.seen);
            }
        }
        Some("unpin") => {
            let Some(file) = files.iter_mut().find(|file| file.id == id) else {
                return;
            };
            let slot = op["slot"].as_u64().unwrap_or(0);
            file.replicas.retain(|replica| replica.slot != slot);
        }
        Some("drop") => files.retain(|file| file.id != id),
        _ => {}
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| items.iter().filter_map(|item| item.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

pub struct Store {
    pub dir: PathBuf,
    pub identity: Identity,
    pub device: Device,
    pub journal: Value,
}

impl Store {
    pub fn create(dir: &Path, identity: Identity, device_id: [u8; 16]) -> Result<Self, VaultError> {
        fs::create_dir_all(dir.join("blobs")).map_err(|e| err(&e.to_string()))?;
        let device = derive_device(&identity.seed, &device_id);
        let mut journal = json!({"v": 1, "devices": [], "ops": []});
        enroll(&mut journal, &identity, &device);
        let store = Self {
            dir: dir.to_path_buf(),
            identity,
            device,
            journal,
        };
        store.write_map()?;
        Ok(store)
    }

    pub fn open(dir: &Path, identity: Identity, device_id: [u8; 16]) -> Result<Self, VaultError> {
        let packed = fs::read(dir.join("map.bin")).map_err(|_| err("нет map.bin"))?;
        let journal = load_journal(&packed, &identity.vault_key)?;
        let device = derive_device(&identity.seed, &device_id);
        fold_journal(&journal, &identity.ed_pub)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            identity,
            device,
            journal,
        })
    }

    pub fn files(&self) -> Result<Vec<FileRec>, VaultError> {
        fold_journal(&self.journal, &self.identity.ed_pub)
    }

    pub fn add_file(&mut self, id: &str, name: &str, bytes: &[u8]) -> Result<FileRec, VaultError> {
        if bytes.len() > 4096 * CHUNK_BYTES {
            return Err(err("файл больше 64 МБ"));
        }
        let count = if bytes.is_empty() { 1 } else { (bytes.len() + CHUNK_BYTES - 1) / CHUNK_BYTES };
        let file_key = random32()?;
        let prefix = random16()?;
        let mut cids = Vec::new();
        for index in 0..count {
            let start = index * CHUNK_BYTES;
            let end = (start + CHUNK_BYTES).min(bytes.len());
            let slice = if start >= bytes.len() { &[][..] } else { &bytes[start..end] };
            let (cid, ct) = seal_chunk(&file_key, &pad_chunk(slice), &prefix, index as u32, 0)?;
            write_blob(&self.dir.join("blobs"), &cid, &ct)?;
            cids.push(Value::String(cid));
        }
        let mut op = Map::new();
        op.insert("op".into(), json!("add"));
        op.insert("id".into(), json!(id));
        op.insert("name".into(), json!(name));
        op.insert("size".into(), json!(bytes.len() as u64));
        op.insert("hash".into(), json!(hex::encode(Sha256::digest(bytes))));
        op.insert("fileKey".into(), json!(hex::encode(file_key)));
        op.insert("localPrefix".into(), json!(hex::encode(prefix)));
        op.insert("chunks".into(), Value::Array(cids));
        op.insert("dev".into(), json!(hex::encode(self.device.ed_pub)));
        op.insert("at".into(), json!(now_ms()));
        self.push_op(sign_op(op, &self.device))?;
        self.files()?.into_iter().find(|file| file.id == id).ok_or_else(|| err("файл не записан"))
    }

    pub fn read_file(&self, id: &str) -> Result<Vec<u8>, VaultError> {
        let file = self.files()?.into_iter().find(|file| file.id == id).ok_or_else(|| err("Файл не найден."))?;
        let key = decode32(&file.file_key)?;
        let mut out = vec![0u8; file.size as usize];
        for (index, cid) in file.chunks.iter().enumerate() {
            let ct = fs::read(blob_path(&self.dir.join("blobs"), cid)).map_err(|_| err("чанк не найден"))?;
            if hex::encode(Sha256::digest(&ct)) != *cid {
                return Err(err("локальный чанк подменён"));
            }
            let padded = open_chunk(&key, &ct, &file.local_prefix, index as u32, 0)?;
            let start = index * CHUNK_BYTES;
            let take = if index + 1 == file.chunks.len() {
                file.size as usize - start
            } else {
                CHUNK_BYTES
            };
            out[start..start + take].copy_from_slice(&padded[..take]);
        }
        if hex::encode(Sha256::digest(&out)) != file.hash {
            return Err(err("хеш файла не сошёлся"));
        }
        Ok(out)
    }

    fn push_op(&mut self, op: Value) -> Result<(), VaultError> {
        self.journal["ops"].as_array_mut().ok_or_else(|| err("журнал"))?.push(op);
        fold_journal(&self.journal, &self.identity.ed_pub)?;
        self.write_map()
    }

    fn write_map(&self) -> Result<(), VaultError> {
        let packed = save_journal(&self.journal, &self.identity.vault_key)?;
        fs::write(self.dir.join("map.bin"), packed).map_err(|e| err(&e.to_string()))
    }
}

fn enroll(journal: &mut Value, identity: &Identity, device: &Device) {
    let pub_hex = hex::encode(device.ed_pub);
    let exists = journal["devices"]
        .as_array()
        .map(|devices| devices.iter().any(|item| item["pub"].as_str() == Some(pub_hex.as_str())))
        .unwrap_or(false);
    if exists {
        return;
    }
    let cert = hex::encode(ed25519_sign(&identity.ed_priv, &cert_message(&device.ed_pub)));
    journal["devices"]
        .as_array_mut()
        .expect("devices")
        .push(json!({"pub": pub_hex, "cert": cert}));
}

fn write_blob(root: &Path, cid: &str, ct: &[u8]) -> Result<(), VaultError> {
    let path = blob_path(root, cid);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| err(&e.to_string()))?;
    }
    fs::write(path, ct).map_err(|e| err(&e.to_string()))
}

fn blob_path(root: &Path, cid: &str) -> PathBuf {
    root.join(&cid[..2]).join(cid)
}

fn random32() -> Result<[u8; 32], VaultError> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| err("нет случайности"))?;
    Ok(raw)
}

fn random16() -> Result<[u8; 16], VaultError> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|_| err("нет случайности"))?;
    Ok(raw)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn decode32(text: &str) -> Result<[u8; 32], VaultError> {
    let bytes = hex::decode(text).map_err(|_| err("не hex"))?;
    bytes.try_into().map_err(|_| err("не 32 байта"))
}

fn decode64(text: &str) -> Result<[u8; 64], VaultError> {
    let bytes = hex::decode(text).map_err(|_| err("не hex"))?;
    bytes.try_into().map_err(|_| err("не 64 байта"))
}
