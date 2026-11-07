//! `identity.bin` закрыт `machine.key` тем же кадром, что Linux 0.10.0.
//! В файле фраза и идентификатор устройства. Журнал от этого ключа не меняется.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use nexxus_crypto::{open_packed, seal_packed, Identity};
use serde_json::json;

pub struct Account {
    pub identity: Identity,
    pub device_id: [u8; 16],
    /// Слова, которые надо показать один раз. Повторный запуск их не возвращает.
    pub fresh_words: Option<String>,
}

pub fn load_account(dir: &Path, mnemonic: Option<&str>) -> Result<Account, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let key_path = dir.join("machine.key");
    let id_path = dir.join("identity.bin");
    let machine = if key_path.is_file() {
        let bytes = fs::read(&key_path).map_err(|e| e.to_string())?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| "machine.key не 32 байта")?;
        array
    } else {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|_| "нет случайности")?;
        write_secret(&key_path, &raw)?;
        raw
    };
    let (phrase, device_id, fresh) = if id_path.is_file() {
        let packed = fs::read(&id_path).map_err(|e| e.to_string())?;
        let plain = open_packed(&machine, &packed).map_err(|_| "identity.bin не открывается этим machine.key".to_string())?;
        let saved: serde_json::Value = serde_json::from_slice(&plain).map_err(|_| "identity.bin повреждён".to_string())?;
        let phrase = saved["mnemonic"].as_str().ok_or("в identity.bin нет фразы")?.to_string();
        let device_hex = saved["deviceId"].as_str().ok_or("в identity.bin нет устройства")?;
        (phrase, decode16(device_hex)?, false)
    } else if let Some(words) = mnemonic {
        (words.trim().to_string(), random16()?, true)
    } else {
        (nexxus_crypto::create_mnemonic().map_err(|e| e.0)?, random16()?, true)
    };
    let identity = Identity::from_mnemonic(&phrase).map_err(|e| e.0)?;
    let body = json!({
        "mnemonic": identity_phrase(&phrase),
        "fingerprint": identity.fingerprint(),
        "pubHex": identity.pub_hex(),
        "deviceId": hex::encode(device_id),
    });
    let packed = seal_packed(&machine, body.to_string().as_bytes()).map_err(|e| e.0)?;
    write_secret(&id_path, &packed)?;
    Ok(Account {
        identity,
        device_id,
        fresh_words: if fresh { Some(identity_phrase(&phrase)) } else { None },
    })
}

fn identity_phrase(phrase: &str) -> String {
    phrase.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode16(text: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(text).map_err(|_| "deviceId не hex".to_string())?;
    bytes.try_into().map_err(|_| "deviceId не 16 байт".to_string())
}

fn random16() -> Result<[u8; 16], String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|_| "нет случайности")?;
    Ok(raw)
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())
}
