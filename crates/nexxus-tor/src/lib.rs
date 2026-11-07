//! Запуск уже установленного `tor`. Свой onion-ключ здесь не создаётся.
//! Нет файла `hostname` с настоящим v3 — старт с ошибкой, адрес не подставляется.

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nexxus_crypto::is_onion;

pub fn render_torrc(data_dir: &Path, socks_port: u16, hs_dir: &Path, port: u16) -> String {
    format!(
        "DataDirectory {data}\nSocksPort 127.0.0.1:{socks_port}\nHiddenServiceDir {hs}\nHiddenServicePort {port} 127.0.0.1:{port}\nClientOnly 1\nLog notice stdout\n",
        data = quote(&data_dir.display().to_string()),
        hs = quote(&hs_dir.display().to_string()),
    )
}

#[derive(Debug)]
pub struct Tor {
    child: Child,
    pub onion: String,
    pub socks_port: u16,
}

impl Tor {
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Tor {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start_tor(bin: &str, root: &Path, listen_port: u16, timeout: Duration) -> Result<Tor, String> {
    let data_dir = root.join("data");
    let hs_dir = root.join("hs");
    fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&hs_dir).map_err(|e| e.to_string())?;
    restrict_dir(&hs_dir)?;
    let socks_port = free_port()?;
    let torrc = root.join("torrc");
    fs::write(&torrc, render_torrc(&data_dir, socks_port, &hs_dir, listen_port)).map_err(|e| e.to_string())?;
    let parent = PathBuf::from(bin).parent().map(|path| path.display().to_string()).unwrap_or_default();
    let inherited = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
    let library_path = [parent, inherited].into_iter().filter(|item| !item.is_empty()).collect::<Vec<_>>().join(":");
    let mut command = Command::new(bin);
    command.arg("-f").arg(&torrc).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if !library_path.is_empty() {
        command.env("LD_LIBRARY_PATH", library_path);
    }
    let mut child = command.spawn().map_err(|err| format!("Не удалось запустить Tor ({bin}): {err}"))?;
    let log = Arc::new(Mutex::new(String::new()));
    pipe_to_log(child.stdout.take(), log.clone());
    pipe_to_log(child.stderr.take(), log.clone());
    let hostname = hs_dir.join("hostname");
    let started = Instant::now();
    let mut onion = String::new();
    while started.elapsed() < timeout {
        if let Some(code) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("Tor завершился сразу, код {code}. {}", tail(&log)));
        }
        if let Ok(text) = fs::read_to_string(&hostname) {
            let first = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if is_onion(&first) {
                onion = first;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    if onion.is_empty() {
        let _ = child.kill();
        return Err(format!("Tor не записал v3-адрес в hostname. Адрес не подставляется. {}", tail(&log)));
    }
    let marked = Instant::now();
    while started.elapsed() < timeout {
        let text = log.lock().map(|guard| guard.clone()).unwrap_or_default();
        if text.contains("Bootstrapped 100%") || (!text.contains("Bootstrapped") && marked.elapsed() > Duration::from_millis(1500)) {
            break;
        }
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(Tor { child, onion, socks_port })
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    Ok(port)
}

fn pipe_to_log(pipe: Option<impl Read + Send + 'static>, log: Arc<Mutex<String>>) {
    let Some(mut pipe) = pipe else { return };
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok(n) = pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            if let Ok(mut text) = log.lock() {
                text.push_str(&String::from_utf8_lossy(&buf[..n]));
                if text.len() > 2000 {
                    let keep = text.len() - 2000;
                    text.replace_range(..keep, "");
                }
            }
        }
    });
}

fn tail(log: &Mutex<String>) -> String {
    log.lock().map(|text| text.trim().to_string()).unwrap_or_default()
}
