//! Ключи и кадр NeXXXUs. Совпадает с Linux-нодой 0.10.0, сеть здесь не живёт.

use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub struct CryptoError(pub String);

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CryptoError {}

fn err(text: &str) -> CryptoError {
    CryptoError(text.to_string())
}

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("hkdf 32");
    out
}

pub fn create_mnemonic() -> Result<String, CryptoError> {
    let mut entropy = [0u8; 16];
    getrandom::getrandom(&mut entropy).map_err(|_| err("нет случайности"))?;
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|_| err("не удалось собрать фразу"))?;
    Ok(mnemonic.to_string())
}

pub fn fingerprint_from_pub(public: &[u8]) -> String {
    let digest = Sha256::digest(public);
    format!("nxx1{}", hex::encode(&digest[..8]))
}

#[derive(Clone)]
pub struct Identity {
    pub x_priv: [u8; 32],
    pub x_pub: [u8; 32],
    pub ed_priv: [u8; 32],
    pub ed_pub: [u8; 32],
    pub vault_key: [u8; 32],
    pub seed: [u8; 64],
}

impl Identity {
    pub fn from_mnemonic(phrase: &str) -> Result<Self, CryptoError> {
        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase.trim())
            .map_err(|_| err("фраза BIP39 не разобрана"))?;
        if mnemonic.word_count() != 12 {
            return Err(err("нужны ровно 12 слов"));
        }
        let seed = mnemonic.to_seed("");
        Ok(Self::from_seed(seed))
    }

    pub fn from_seed(seed: [u8; 64]) -> Self {
        let x_priv = hkdf32(&seed, b"nexxus-x25519", b"v1");
        let ed_priv = hkdf32(&seed, b"nexxus-ed25519", b"v1");
        let vault_key = hkdf32(&seed, b"nexxus-vault", b"v1");
        let x_pub = x25519_public(&x_priv);
        let ed_pub = ed25519_public(&ed_priv);
        Self {
            x_priv,
            x_pub,
            ed_priv,
            ed_pub,
            vault_key,
            seed,
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_from_pub(&self.x_pub)
    }

    pub fn pub_hex(&self) -> String {
        hex::encode(self.x_pub)
    }

    pub fn ed_hex(&self) -> String {
        hex::encode(self.ed_pub)
    }
}

pub fn ephemeral() -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| err("нет случайности"))?;
    let secret = StaticSecret::from(raw);
    let public = PublicKey::from(&secret);
    Ok((secret.to_bytes(), public.to_bytes()))
}

pub fn seal_packed(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| err("нет случайности"))?;
    let mut out = nonce.to_vec();
    out.extend(seal(key, &nonce, plain)?);
    Ok(out)
}

pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

pub fn x25519_shared(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    if public.iter().all(|b| *b == 0) {
        return Err(err("слабый публичный ключ"));
    }
    let secret = StaticSecret::from(*secret);
    let public = PublicKey::from(*public);
    Ok(secret.diffie_hellman(&public).to_bytes())
}

pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

pub fn ed25519_verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    key.verify(message, &sig).is_ok()
}

pub fn derive_session_key(
    my_static_priv: &[u8; 32],
    my_static_pub: &[u8; 32],
    my_eph_priv: &[u8; 32],
    their_static_pub: &[u8; 32],
    their_eph_pub: &[u8; 32],
    initiator: bool,
) -> Result<[u8; 32], CryptoError> {
    let ss = x25519_shared(my_static_priv, their_static_pub)?;
    let ee = x25519_shared(my_eph_priv, their_eph_pub)?;
    let (es, se) = if initiator {
        (
            x25519_shared(my_eph_priv, their_static_pub)?,
            x25519_shared(my_static_priv, their_eph_pub)?,
        )
    } else {
        (
            x25519_shared(my_static_priv, their_eph_pub)?,
            x25519_shared(my_eph_priv, their_static_pub)?,
        )
    };
    let mut ikm = Vec::with_capacity(128);
    ikm.extend_from_slice(&ss);
    ikm.extend_from_slice(&ee);
    ikm.extend_from_slice(&es);
    ikm.extend_from_slice(&se);
    let mine = hex::encode(my_static_pub);
    let theirs = hex::encode(their_static_pub);
    let (first, second) = if mine < theirs {
        (my_static_pub, their_static_pub)
    } else {
        (their_static_pub, my_static_pub)
    };
    let mut salt = b"nexxus-session".to_vec();
    salt.extend_from_slice(first);
    salt.extend_from_slice(second);
    Ok(hkdf32(&ikm, &salt, b"nxxp2"))
}

#[derive(Clone, Debug)]
pub struct Hello {
    pub fingerprint: String,
    pub public_hex: String,
    pub eph_hex: String,
    pub ed_hex: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub signature_hex: String,
}

impl Hello {
    fn canon(&self) -> Vec<u8> {
        format!(
            "3|hello|{}|{}|{}|{}|{}|{}|{}",
            self.fingerprint, self.public_hex, self.eph_hex, self.ed_hex, self.name, self.host, self.port
        )
        .into_bytes()
    }

    pub fn sign(
        identity: &Identity,
        eph_hex: &str,
        name: &str,
        host: &str,
        port: u16,
    ) -> Self {
        let mut hello = Self {
            fingerprint: identity.fingerprint(),
            public_hex: identity.pub_hex(),
            eph_hex: eph_hex.to_ascii_lowercase(),
            ed_hex: identity.ed_hex(),
            name: name.to_string(),
            host: host.to_string(),
            port,
            signature_hex: String::new(),
        };
        hello.signature_hex = hex::encode(ed25519_sign(&identity.ed_priv, &hello.canon()));
        hello
    }

    pub fn verify(&self) -> Result<(), CryptoError> {
        let public = decode32(&self.public_hex).map_err(|_| err("битые поля hello"))?;
        let ed = decode32(&self.ed_hex).map_err(|_| err("битые поля hello"))?;
        decode32(&self.eph_hex).map_err(|_| err("битые поля hello"))?;
        let signature = decode64(&self.signature_hex).map_err(|_| err("битые поля hello"))?;
        if fingerprint_from_pub(&public) != self.fingerprint.to_ascii_lowercase() {
            return Err(err("отпечаток не от этого X25519 ключа"));
        }
        if !ed25519_verify(&ed, &self.canon(), &signature) {
            return Err(err("подпись hello не сходится"));
        }
        Ok(())
    }
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 24], plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(XNonce::from_slice(nonce), plain)
        .map_err(|_| err("не запечаталось"))
}

pub fn open_packed(key: &[u8; 32], packed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if packed.len() < 24 + 16 {
        return Err(err("короткий кадр"));
    }
    let (nonce, ct) = packed.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| err("бирка не сошлась"))
}

#[derive(Clone, Debug)]
pub struct Contact {
    pub fingerprint: String,
    pub public_hex: String,
    pub host: String,
    pub port: u16,
}

pub fn format_contact(contact: &Contact) -> String {
    format!(
        "nexxus:1:{}:{}@{}:{}",
        contact.fingerprint, contact.public_hex, contact.host, contact.port
    )
}

pub fn parse_contact(uri: &str) -> Result<Contact, CryptoError> {
    let raw = uri.trim();
    let Some(rest) = raw.strip_prefix("nexxus:1:") else {
        return Err(err("Контакт должен выглядеть как nexxus:1:nxx1…:ключ@хост:порт"));
    };
    let Some((fp, after_fp)) = rest.split_once(':') else {
        return Err(err("Контакт должен выглядеть как nexxus:1:nxx1…:ключ@хост:порт"));
    };
    let Some((public_hex, after_pub)) = after_fp.split_once('@') else {
        return Err(err("Контакт должен выглядеть как nexxus:1:nxx1…:ключ@хост:порт"));
    };
    let Some((host, port_text)) = after_pub.rsplit_once(':') else {
        return Err(err("Контакт должен выглядеть как nexxus:1:nxx1…:ключ@хост:порт"));
    };
    if !fp.to_ascii_lowercase().starts_with("nxx1")
        || public_hex.len() != 64
        || !public_hex.chars().all(|c| c.is_ascii_hexdigit())
        || host.is_empty()
        || host.contains([' ', '@'])
    {
        return Err(err("Контакт должен выглядеть как nexxus:1:nxx1…:ключ@хост:порт"));
    }
    let port: u16 = port_text.parse().map_err(|_| err("Некорректный порт в контакте."))?;
    if port == 0 {
        return Err(err("Некорректный порт в контакте."));
    }
    let public = decode32(&public_hex.to_ascii_lowercase())?;
    let fingerprint = fp.to_ascii_lowercase();
    if fingerprint_from_pub(&public) != fingerprint {
        return Err(err("Отпечаток не совпадает с публичным ключом."));
    }
    Ok(Contact {
        fingerprint,
        public_hex: hex::encode(public),
        host: host.to_string(),
        port,
    })
}

fn decode32(text: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = hex::decode(text).map_err(|_| err("не hex"))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| err("не 32 байта"))?;
    Ok(array)
}

fn decode64(text: &str) -> Result<[u8; 64], CryptoError> {
    let bytes = hex::decode(text).map_err(|_| err("не hex"))?;
    let array: [u8; 64] = bytes.try_into().map_err(|_| err("не 64 байта"))?;
    Ok(array)
}
