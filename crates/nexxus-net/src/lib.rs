//! Лабораторный TCP. Сначала открытый HELLO v3, дальше кадры XChaCha20-Poly1305.
//! Лука и сейфа здесь нет.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nexxus_crypto::{
    derive_session_key, format_contact, is_onion, open_packed, parse_contact, seal_packed, Contact, Hello, Identity,
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
pub type UpHandler = Arc<dyn Fn(&str) + Send + Sync>;

struct Inner {
    identity: Identity,
    name: String,
    advertise: String,
    bind: String,
    port: u16,
    stop: std::sync::atomic::AtomicBool,
    peers: Mutex<HashMap<String, PeerOut>>,
    inbox: Mutex<Vec<ChatLine>>,
    ready: Condvar,
    on_packet: Mutex<Option<PacketHandler>>,
    profile: Mutex<String>,
    socks_host: Mutex<String>,
    socks_port: Mutex<u16>,
    eds: Mutex<HashMap<String, String>>,
    on_up: Mutex<Option<UpHandler>>,
}

#[derive(Clone)]
pub struct Mesh {
    inner: Arc<Inner>,
}

impl Mesh {
    pub fn listen(identity: Identity, name: &str, advertise: &str, port: u16) -> std::io::Result<Self> {
        Self::listen_on("127.0.0.1", identity, name, advertise, port)
    }

    pub fn listen_on(bind_host: &str, identity: Identity, name: &str, advertise: &str, port: u16) -> std::io::Result<Self> {
        let listener = TcpListener::bind((bind_host, port))?;
        let port = listener.local_addr()?.port();
        let mesh = Self {
            inner: Arc::new(Inner {
                identity,
                name: name.to_string(),
                advertise: advertise.to_string(),
                bind: bind_host.to_string(),
                port,
                stop: std::sync::atomic::AtomicBool::new(false),
                peers: Mutex::new(HashMap::new()),
                inbox: Mutex::new(Vec::new()),
                ready: Condvar::new(),
                on_packet: Mutex::new(None),
                profile: Mutex::new("lab".into()),
                socks_host: Mutex::new(String::new()),
                socks_port: Mutex::new(0),
                eds: Mutex::new(HashMap::new()),
                on_up: Mutex::new(None),
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

    pub fn set_route(&self, profile: &str, socks: Option<(&str, u16)>) -> Result<(), String> {
        if profile != "lab" && profile != "onion" {
            return Err("Профиль только lab или onion.".into());
        }
        if profile == "onion" && socks.map(|(_, port)| port == 0).unwrap_or(true) {
            return Err("Не задан Tor SOCKS.".into());
        }
        *self.inner.profile.lock().map_err(|_| "замок")? = profile.to_string();
        if let Some((host, port)) = socks {
            *self.inner.socks_host.lock().map_err(|_| "замок")? = host.to_string();
            *self.inner.socks_port.lock().map_err(|_| "замок")? = port;
        }
        Ok(())
    }

    pub fn dial(&self, uri: &str) -> Result<(), String> {
        let contact = parse_contact(uri).map_err(|e| e.0)?;
        let onion = is_onion(&contact.host);
        let profile = self.inner.profile.lock().map_err(|_| "замок")?.clone();
        if profile == "onion" && !onion {
            return Err("В луковом профиле контакт обязан быть v3 .onion.".into());
        }
        if profile != "onion" && onion {
            return Err("Луковый контакт нельзя звать из лабораторного TCP. Нужен --profile onion.".into());
        }
        let stream = if profile == "onion" {
            let host = self.inner.socks_host.lock().map_err(|_| "замок")?.clone();
            let port = *self.inner.socks_port.lock().map_err(|_| "замок")?;
            if host.is_empty() || port == 0 {
                return Err("Не задан Tor SOCKS.".into());
            }
            connect_via_socks(&host, port, &contact.host, contact.port)?
        } else {
            let address = format!("{}:{}", contact.host, contact.port);
            TcpStream::connect(&address).map_err(|e| e.to_string())?
        };
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

    pub fn set_on_up(&self, handler: UpHandler) {
        *self.inner.on_up.lock().expect("up") = Some(handler);
    }

    pub fn peer_ed(&self, fingerprint: &str) -> Option<String> {
        self.inner.eds.lock().ok().and_then(|eds| eds.get(fingerprint).cloned())
    }

    pub fn peers(&self) -> Vec<String> {
        self.inner
            .peers
            .lock()
            .map(|peers| peers.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub fn chats(&self) -> Vec<ChatLine> {
        self.inner.inbox.lock().map(|inbox| inbox.clone()).unwrap_or_default()
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
        let hello_wait = if self.inner.profile.lock().map(|profile| profile.as_str() == "onion").unwrap_or(false) {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(12)
        };
        stream.set_read_timeout(Some(hello_wait)).map_err(|e| e.to_string())?;
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
        self.inner.eds.lock().ok().map(|mut eds| eds.insert(remote.fingerprint.clone(), remote.ed_hex.clone()));
        if let Some(on_up) = self.inner.on_up.lock().ok().and_then(|guard| guard.clone()) {
            on_up(&remote.fingerprint);
        }
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
        let host = if self.inner.bind == "0.0.0.0" || self.inner.bind == "::" {
            "127.0.0.1"
        } else {
            &self.inner.bind
        };
        let _ = TcpStream::connect((host, self.inner.port));
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

fn connect_via_socks(socks_host: &str, socks_port: u16, host: &str, port: u16) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(format!("{socks_host}:{socks_port}")).map_err(|e| format!("SOCKS {host}:{port} — {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
    stream.write_all(&[5, 1, 0]).map_err(|e| e.to_string())?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).map_err(|e| format!("SOCKS {host}:{port} — {e}"))?;
    if greeting != [5, 0] {
        return Err("SOCKS не принял соединение без пароля.".into());
    }
    let name = host.as_bytes();
    if name.is_empty() || name.len() > 255 {
        return Err("Адрес для SOCKS пустой или слишком длинный.".into());
    }
    let mut req = vec![5, 1, 0, 3, name.len() as u8];
    req.extend_from_slice(name);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).map_err(|e| e.to_string())?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).map_err(|e| format!("SOCKS {host}:{port} — {e}"))?;
    if head[0] != 5 {
        return Err("SOCKS вернул неизвестный тип адреса.".into());
    }
    let extra = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(|e| e.to_string())?;
            usize::from(len[0]) + 2
        }
        _ => return Err("SOCKS вернул неизвестный тип адреса.".into()),
    };
    let mut rest = vec![0u8; extra];
    stream.read_exact(&mut rest).map_err(|e| e.to_string())?;
    if head[1] != 0 {
        return Err(format!("SOCKS отказал в соединении, код {}.", head[1]));
    }
    stream.set_read_timeout(None).map_err(|e| e.to_string())?;
    Ok(stream)
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
