//! Очередь `nexxus-smp-v1` и описание `nexxus-xftp-v1`.
//! Это не провод simplexmq. В описании нет адресов узлов.

use nexxus_crypto::{ed25519_sign, ed25519_verify, ephemeral, seal, x25519_public, x25519_shared, Identity};
use nexxus_vault::{open_chunk, pad_chunk, seal_chunk, CHUNK_BYTES};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const SMP_INFO: &[u8] = b"nexxus-smp-v1";

#[derive(Clone, Debug)]
pub struct Sealed {
    pub eph: String,
    pub nonce: String,
    pub ct: String,
}

pub struct QueueKey {
    pub priv_key: [u8; 32],
    pub pub_hex: String,
}

pub fn create_queue_key() -> Result<QueueKey, String> {
    let (priv_key, public) = ephemeral().map_err(|e| e.0)?;
    Ok(QueueKey { priv_key, pub_hex: hex::encode(public) })
}

pub fn seal_queue(recipient_pub: &[u8; 32], plain: &[u8]) -> Result<Sealed, String> {
    let (eph_priv, eph_pub) = ephemeral().map_err(|e| e.0)?;
    seal_queue_with(&eph_priv, &eph_pub, recipient_pub, &random24()?, plain)
}

pub fn seal_queue_with(eph_priv: &[u8; 32], eph_pub: &[u8; 32], recipient_pub: &[u8; 32], nonce: &[u8; 24], plain: &[u8]) -> Result<Sealed, String> {
    let key = queue_key(eph_priv, recipient_pub)?;
    let ct = seal(&key, nonce, plain).map_err(|e| e.0)?;
    Ok(Sealed {
        eph: hex::encode(eph_pub),
        nonce: hex::encode(nonce),
        ct: hex::encode(ct),
    })
}

pub fn open_queue(recipient_priv: &[u8; 32], message: &Sealed) -> Result<Vec<u8>, String> {
    let eph = decode32(&message.eph)?;
    let nonce = decode24(&message.nonce)?;
    let ct = hex::decode(&message.ct).map_err(|_| "шифртекст очереди не hex")?;
    let key = queue_key(recipient_priv, &eph)?;
    let mut packed = nonce.to_vec();
    packed.extend(ct);
    nexxus_crypto::open_packed(&key, &packed).map_err(|e| e.0)
}

pub fn verify_desc(desc: &Value) -> bool {
    if desc["v"] != 1 || truthy(desc, "host") || truthy(desc, "port") {
        return false;
    }
    let Some(cids) = desc["cids"].as_array() else { return false };
    if cids.is_empty() || cids.len() > 4096 {
        return false;
    }
    let (Some(sig_hex), Some(pub_hex)) = (desc["sig"].as_str(), desc["pub"].as_str()) else {
        return false;
    };
    let (Ok(sig), Ok(public)) = (decode64(sig_hex), decode32(pub_hex)) else {
        return false;
    };
    let mut body = desc.clone();
    body.as_object_mut().map(|map| map.remove("sig"));
    ed25519_verify(&public, &xftp_message(&body), &sig)
}

pub fn pack_xftp(name: &str, bytes: &[u8], identity: &Identity) -> Result<(Value, Vec<Vec<u8>>), String> {
    let file_key = random32()?;
    let prefix = random16()?;
    let chunks = if bytes.is_empty() { 1 } else { bytes.len().div_ceil(CHUNK_BYTES) };
    let mut cids = Vec::new();
    let mut bodies = Vec::new();
    for index in 0..chunks {
        let start = index * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(bytes.len());
        let slice = if start >= bytes.len() { &[][..] } else { &bytes[start..end] };
        let (cid, ct) = seal_chunk(&file_key, &pad_chunk(slice), &prefix, index as u32, 0).map_err(|e| e.0)?;
        cids.push(Value::String(cid));
        bodies.push(ct);
    }
    let mut body = Map::new();
    body.insert("v".into(), Value::from(1));
    body.insert("name".into(), Value::String(name.to_string()));
    body.insert("size".into(), Value::from(bytes.len() as u64));
    body.insert("hash".into(), Value::String(hex::encode(Sha256::digest(bytes))));
    body.insert("fileKey".into(), Value::String(hex::encode(file_key)));
    body.insert("prefix".into(), Value::String(hex::encode(prefix)));
    body.insert("cids".into(), Value::Array(cids));
    body.insert("pub".into(), Value::String(hex::encode(identity.ed_pub)));
    let message = xftp_message(&Value::Object(body.clone()));
    let sig = hex::encode(ed25519_sign(&identity.ed_priv, &message));
    body.insert("sig".into(), Value::String(sig));
    let desc = Value::Object(body);
    if desc.get("host").is_some() || desc.get("port").is_some() {
        return Err("в описании XFTP не должно быть адреса".into());
    }
    Ok((desc, bodies))
}

pub fn unpack_xftp(desc: &Value, bodies: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if !verify_desc(desc) {
        return Err("описание XFTP не сошлось".into());
    }
    let cids = desc["cids"].as_array().ok_or("описание XFTP не сошлось")?;
    if bodies.len() != cids.len() {
        return Err("не все чанки описания на месте".into());
    }
    let size = desc["size"].as_u64().ok_or("описание XFTP не сошлось")? as usize;
    let mut out = vec![0u8; size];
    for (index, body) in bodies.iter().enumerate() {
        let cid = cids[index].as_str().unwrap_or("");
        if hex::encode(Sha256::digest(body)) != cid {
            return Err("чанк не совпал с описанием".into());
        }
        let key = decode32(desc["fileKey"].as_str().unwrap_or(""))?;
        let plain = open_chunk(&key, body, desc["prefix"].as_str().unwrap_or(""), index as u32, 0).map_err(|e| e.0)?;
        let take = if index + 1 == cids.len() { size - index * CHUNK_BYTES } else { CHUNK_BYTES };
        let start = index * CHUNK_BYTES;
        out[start..start + take].copy_from_slice(&plain[..take]);
    }
    if hex::encode(Sha256::digest(&out)) != desc["hash"].as_str().unwrap_or("") {
        return Err("хеш XFTP не сошёлся".into());
    }
    Ok(out)
}

pub fn miner_message(fingerprint: &str, supply: u64) -> Vec<u8> {
    format!("nexxus-miner-v1|{fingerprint}|{supply}").into_bytes()
}

pub fn sign_miner(identity: &Identity, supply: u64) -> String {
    hex::encode(ed25519_sign(&identity.ed_priv, &miner_message(&identity.fingerprint(), supply)))
}

pub fn verify_miner(fingerprint: &str, ed_pub_hex: &str, supply: u64, sig_hex: &str) -> bool {
    let (Ok(public), Ok(sig)) = (decode32(ed_pub_hex), decode64(sig_hex)) else {
        return false;
    };
    ed25519_verify(&public, &miner_message(fingerprint, supply), &sig)
}

fn queue_key(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], String> {
    let shared = x25519_shared(secret, public).map_err(|e| e.0)?;
    Ok(hkdf32(&shared))
}

fn hkdf32(ikm: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&[]), ikm).expand(SMP_INFO, &mut out).expect("hkdf");
    out
}

fn xftp_message(body: &Value) -> Vec<u8> {
    format!("nexxus-xftp-v1|{}", canon(body)).into_bytes()
}

fn canon(value: &Value) -> String {
    match value {
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canon).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|key| format!("{}:{}", serde_json::to_string(key).unwrap_or_else(|_| "\"\"".into()), canon(&map[key])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".into()),
    }
}

fn truthy(value: &Value, key: &str) -> bool {
    match value.get(key) {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(_) => true,
    }
}

fn random32() -> Result<[u8; 32], String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| "нет случайности")?;
    Ok(raw)
}

fn random16() -> Result<[u8; 16], String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|_| "нет случайности")?;
    Ok(raw)
}

fn random24() -> Result<[u8; 24], String> {
    let mut raw = [0u8; 24];
    getrandom::getrandom(&mut raw).map_err(|_| "нет случайности")?;
    Ok(raw)
}

fn decode32(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|_| "не hex")?;
    bytes.try_into().map_err(|_| "нужно 32 байта".to_string())
}

fn decode24(text: &str) -> Result<[u8; 24], String> {
    let bytes = hex::decode(text).map_err(|_| "не hex")?;
    bytes.try_into().map_err(|_| "нужен nonce".to_string())
}

fn decode64(text: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(text).map_err(|_| "не hex")?;
    bytes.try_into().map_err(|_| "нужна подпись".to_string())
}

pub fn recipient_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_public(secret)
}
