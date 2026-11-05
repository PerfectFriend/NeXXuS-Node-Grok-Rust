//! Лабораторный TCP. Сначала открытый HELLO v3, дальше кадры XChaCha20-Poly1305.
//! Лука и сейфа здесь нет.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexxus_crypto::{
    derive_session_key, format_contact, open_packed, parse_contact, seal_packed, Contact, Hello, Identity,
};

#[derive(Clone, Debug)]
pub struct ChatLine {
    pub from: String,
    pub text: String,
}

struct PeerOut {
    tx: std::sync::mpsc::Sender<String>,
}

pub type PacketHandler = Arc<dyn Fn(&str, serde_json::Value) + Send + Sync>;

struct Inner {
    identity: Identity,
    name: String,
    advertise: String,
    port: u16,
    stop: std::sync::atomic::AtomicBool,
    peers: Mutex<HashMap<String, PeerOut>>,
    inbox: Mutex<Vec<ChatLine>>,
    ready: Condvar,
    on_packet: Mutex<Option<PacketHandler>>,
}

#[derive(Clone)]
pub struct Mesh {
    inner: Arc<Inner>,
}

impl Mesh {
    pub fn listen(identity: Identity, name: &str, advertise: &str, port: u16) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        let port = listener.local_addr()?.port();
        let mesh = Self {
            inner: Arc::new(Inner {
                identity,
                name: name.to_string(),
                advertise: advertise.to_string(),
                port,
                stop: std::sync::atomic::AtomicBool::new(false),
                peers: Mutex::new(HashMap::new()),
                inbox: Mutex::new(Vec::new()),
                ready: Condvar::new(),
                on_packet: Mutex::new(None),
            }),
        };
        let background = mesh.clone();
        thread::spawn(move || background.accept_loop(listener));
        Ok(mesh)
    }

    pub fn port(&self) -> u16 {
        self.inner.port
    }

    pub fn contact(&self) -> String {
        format_contact(&Contact {
            fingerprint: self.inner.identity.fingerprint(),
            public_hex: self.inner.identity.pub_hex(),
            host: self.inner.advertise.clone(),
            port: self.inner.port,
        })
    }

    pub fn dial(&self, uri: &str) -> Result<(), String> {
        let contact = parse_contact(uri).map_err(|e| e.0)?;
        let address = format!("{}:{}", contact.host, contact.port);
        let stream = TcpStream::connect(&address).map_err(|e| e.to_string())?;
        self.spawn_link(stream, false, Some(contact));
        Ok(())
    }

    pub fn send_chat(&self, fingerprint: &str, text: &str) -> Result<(), String> {
        let peers = self.inner.peers.lock().map_err(|_| "замок".to_string())?;
        let peer = peers.get(fingerprint).ok_or("контакт ещё не в сети")?;
        let line = serde_json::json!({
            "t": "chat",
            "id": hex::encode(rand16()),
            "text": text,
            "ts": now_ms(),
        });
        peer.tx.send(line.to_string()).map_err(|_| "канал закрыт".to_string())
    }

    pub fn send_json(&self, fingerprint: &str, body: &serde_json::Value) -> Result<(), String> {
        let peers = self.inner.peers.lock().map_err(|_| "замок".to_string())?;
        let peer = peers.get(fingerprint).ok_or("контакт ещё не в сети")?;
        peer.tx.send(body.to_string()).map_err(|_| "канал закрыт".to_string())
    }

    pub fn set_handler(&self, handler: PacketHandler) {
        *self.inner.on_packet.lock().expect("handler") = Some(handler);
    }

    pub fn peers(&self) -> Vec<String> {
        self.inner
            .peers
            .lock()
            .map(|peers| peers.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn wait_chat(&self, text: &str, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut inbox = self.inner.inbox.lock().expect("inbox");
        loop {
            if inbox.iter().any(|line| line.text == text) {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, _) = self
                .inner
                .ready
                .wait_timeout(inbox, deadline - now)
                .expect("wait");
            inbox = guard;
        }
    }

    fn accept_loop(&self, listener: TcpListener) {
        let _ = listener.set_nonblocking(false);
        while !self.inner.stop.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if self.inner.stop.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    self.spawn_link(stream, true, None);
                }
                Err(_) => break,
            }
        }
    }

    fn spawn_link(&self, stream: TcpStream, inbound: bool, expected: Option<Contact>) {
        let mesh = self.clone();
        thread::spawn(move || {
            if let Err(err) = mesh.run_link(stream, inbound, expected) {
                eprintln!("канал: {err}");
            }
        });
    }

    fn run_link(&self, mut stream: TcpStream, inbound: bool, expected: Option<Contact>) -> Result<(), String> {
        stream
            .set_read_timeout(Some(Duration::from_secs(12)))
            .map_err(|e| e.to_string())?;
        let (eph_priv, eph_pub) = nexxus_crypto::ephemeral().map_err(|e| e.0)?;
        let hello = Hello::sign(
            &self.inner.identity,
            &hex::encode(eph_pub),
            &self.inner.name,
            &self.inner.advertise,
            self.inner.port,
        );
        let outgoing = serde_json::json!({
            "v": 3,
            "t": "hello",
            "fp": hello.fingerprint,
            "pub": hello.public_hex,
            "eph": hello.eph_hex,
            "ed": hello.ed_hex,
            "name": hello.name,
            "host": hello.host,
            "port": hello.port,
            "sig": hello.signature_hex,
        });
        write_frame(&mut stream, outgoing.to_string().as_bytes()).map_err(|e| e.to_string())?;
        let raw = read_frame(&mut stream).map_err(|e| e.to_string())?;
        let msg: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let remote = Hello {
            fingerprint: json_str(&msg, "fp")?,
            public_hex: json_str(&msg, "pub")?,
            eph_hex: json_str(&msg, "eph")?,
            ed_hex: json_str(&msg, "ed")?,
            name: msg["name"].as_str().unwrap_or("").to_string(),
            host: msg["host"].as_str().unwrap_or("").to_string(),
            port: msg["port"].as_u64().unwrap_or(0) as u16,
            signature_hex: json_str(&msg, "sig")?,
        };
        remote.verify().map_err(|e| e.0)?;
        if remote.fingerprint == self.inner.identity.fingerprint() {
            return Err("свой ключ".into());
        }
        if let Some(expect) = &expected {
            if expect.fingerprint != remote.fingerprint || expect.public_hex != remote.public_hex {
                return Err("ключ не совпал с контактом".into());
            }
        }
        let key = derive_session_key(
            &self.inner.identity.x_priv,
            &self.inner.identity.x_pub,
            &eph_priv,
            &decode32(&remote.public_hex)?,
            &decode32(&remote.eph_hex)?,
            !inbound,
        )
        .map_err(|e| e.0)?;
        let _ = stream.set_read_timeout(None);
        let write_key = key;
        let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        self.inner
            .peers
            .lock()
            .map_err(|_| "замок")?
            .insert(remote.fingerprint.clone(), PeerOut { tx });
        let fp = remote.fingerprint.clone();
        let mesh = self.clone();
        thread::spawn(move || {
            while let Ok(body) = rx.recv() {
                if let Ok(frame) = seal_packed(&write_key, body.as_bytes()) {
                    if write_frame(&mut writer, &frame).is_err() {
                        break;
                    }
                }
            }
            mesh.inner.peers.lock().ok().map(|mut peers| peers.remove(&fp));
        });
        loop {
            let frame = match read_frame(&mut stream) {
                Ok(frame) => frame,
                Err(_) => break,
            };
            let plain = match open_packed(&key, &frame) {
                Ok(plain) => plain,
                Err(_) => break,
            };
            let Ok(obj) = serde_json::from_slice::<serde_json::Value>(&plain) else {
                continue;
            };
            if obj["t"] == "chat" {
                if let Some(text) = obj["text"].as_str() {
                    self.inner.inbox.lock().expect("inbox").push(ChatLine {
                        from: remote.fingerprint.clone(),
                        text: text.to_string(),
                    });
                    self.inner.ready.notify_all();
                }
            }
            if let Some(handler) = self.inner.on_packet.lock().ok().and_then(|guard| guard.clone()) {
                handler(&remote.fingerprint, obj);
            }
        }
        Ok(())
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        self.inner.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.inner.port));
    }
}

fn json_str(value: &serde_json::Value, key: &str) -> Result<String, String> {
    value[key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("нет поля {key}"))
}

fn decode32(text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(text).map_err(|_| "не hex".to_string())?;
    bytes.try_into().map_err(|_| "не 32 байта".to_string())
}

fn rand16() -> [u8; 16] {
    let mut raw = [0u8; 16];
    let _ = getrandom::getrandom(&mut raw);
    raw
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn write_frame(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > 8 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "кадр слишком большой"));
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body)?;
    Ok(body)
}
