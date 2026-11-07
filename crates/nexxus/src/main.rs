use std::path::PathBuf;
use std::time::Duration;

use nexxus_crypto::is_onion;
use nexxus_node::{load_account, Node};
use nexxus_tor::start_tor;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None | Some("help") | Some("--help") | Some("-h") => print_help(),
        Some("start") => start(args.collect()),
        Some("ctl") => ctl(args.collect()),
        Some("version") => println!("nexxus 0.2.0-lab"),
        Some(other) => {
            eprintln!("неизвестная команда: {other}");
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "NeXXXUs Rust 0.2.0-lab\n\n\
         nexxus start [--data DIR] [--port N] [--listen ADDR] [--name NAME]\n\
         [--mnemonic \"12 слов\"] [--contact URI] [--advertise ХОСТ]\n\
         [--profile lab|onion] [--tor-bin PATH] [--tor-socks ХОСТ:ПОРТ]\n\n\
         nexxus ctl --data DIR status|files|chats|peers\n\
         nexxus ctl --data DIR dial 'nexxus:1:…'\n\
         nexxus ctl --data DIR put ФАЙЛ\n\
         nexxus ctl --data DIR chat ОТПЕЧАТОК текст\n\n\
         Лабораторный профиль слушает 0.0.0.0 и публикует адрес этой машины.\n\
         Команды ctl принимаются только с 127.0.0.1.\n\
         Профиль onion запускает бинарник tor и берёт адрес только из hostname.\n\
         Очереди SMP, описания XFTP и панели в этом пакете нет."
    );
}

fn start(args: Vec<String>) {
    let mut port = 4377u16;
    let mut name = "rust".to_string();
    let mut mnemonic = None;
    let mut contact = None;
    let mut data = default_data();
    let mut profile = "lab".to_string();
    let mut tor_bin = "tor".to_string();
    let mut tor_socks = None;
    let mut advertise = None;
    let mut listen = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                port = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(4377);
                i += 2;
            }
            "--name" => {
                name = args.get(i + 1).cloned().unwrap_or(name);
                i += 2;
            }
            "--mnemonic" => {
                mnemonic = args.get(i + 1).cloned();
                i += 2;
            }
            "--data" => {
                data = PathBuf::from(args.get(i + 1).cloned().unwrap_or_else(|| data.display().to_string()));
                i += 2;
            }
            "--contact" => {
                contact = args.get(i + 1).cloned();
                i += 2;
            }
            "--profile" => {
                profile = args.get(i + 1).cloned().unwrap_or_else(|| "lab".into());
                i += 2;
            }
            "--tor-bin" => {
                tor_bin = args.get(i + 1).cloned().unwrap_or(tor_bin);
                i += 2;
            }
            "--tor-socks" => {
                tor_socks = args.get(i + 1).cloned();
                i += 2;
            }
            "--advertise" => {
                advertise = args.get(i + 1).cloned();
                i += 2;
            }
            "--listen" => {
                listen = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                eprintln!("неизвестный аргумент: {other}");
                std::process::exit(2);
            }
        }
    }
    let account = load_account(&data, mnemonic.as_deref()).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    if let Some(words) = &account.fresh_words {
        println!("Фраза (запишите, больше не покажется):\n{words}\n");
    }
    let mut tor_guard = None;
    let (advertise_host, socks) = if profile == "onion" {
        if let Some(host) = advertise.as_deref() {
            if !is_onion(host) {
                eprintln!("Луковый профиль не публикует прямой адрес. Нужен v3 .onion.");
                std::process::exit(1);
            }
            let socks = parse_socks(tor_socks.as_deref()).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
            (host.to_string(), Some(socks))
        } else if tor_socks.is_some() {
            eprintln!("С готовым SOCKS нужен --advertise и v3 .onion. Сам адрес не подставляется.");
            std::process::exit(1);
        } else {
            let tor = start_tor(&tor_bin, &data.join("tor"), port, std::time::Duration::from_secs(90)).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });
            let host = tor.onion.clone();
            let socks = ("127.0.0.1".to_string(), tor.socks_port);
            tor_guard = Some(tor);
            (host, Some(socks))
        }
    } else if profile == "lab" {
        if advertise.as_deref().is_some_and(is_onion) {
            eprintln!("Лабораторный профиль не публикует .onion. Запустите с --profile onion.");
            std::process::exit(1);
        }
        (advertise.unwrap_or_else(|| lan_ipv4().unwrap_or_else(|| "127.0.0.1".into())), None)
    } else {
        eprintln!("Профиль только lab или onion.");
        std::process::exit(2);
    };
    let bind = if profile == "onion" {
        "127.0.0.1".to_string()
    } else {
        listen.unwrap_or_else(|| "0.0.0.0".into())
    };
    let socks_ref = socks.as_ref().map(|(host, port)| (host.as_str(), *port));
    let node = Node::start_with(
        &data,
        account.identity,
        account.device_id,
        &name,
        port,
        &bind,
        &advertise_host,
        &profile,
        socks_ref,
    )
    .unwrap_or_else(|e| {
        eprintln!("не поднялась: {e}");
        std::process::exit(1);
    });
    let control = node.serve_control(port.saturating_add(1)).or_else(|_| node.serve_control(0)).unwrap_or_else(|e| {
        eprintln!("управляющий порт: {e}");
        std::process::exit(1);
    });
    let _ = std::fs::write(data.join("control.port"), control.to_string());
    let _ = std::fs::write(data.join("contact.txt"), format!("{}\n", node.contact()));
    let _hold_tor = tor_guard;
    let banner = format!(
        "Каталог: {}\nКонтакт: {}\nФайлов в сейфе: {}. Слушаю {bind}:{}.\nУправление: 127.0.0.1:{control}",
        data.display(),
        node.contact(),
        node.file_ids().len(),
        contact_port(&node.contact())
    );
    println!("{banner}");
    append_log(&data, &banner);
    if let Some(uri) = contact {
        if let Err(err) = node.dial(&uri) {
            eprintln!("не дозвонились: {err}");
        }
        loop {
            for id in node.file_ids() {
                if node.copies(&id) >= 3 {
                    continue;
                }
                if let Err(err) = node.replicate_to(&id, &uri) {
                    if err != "нет канала" && err != "этой ноде новые чанки не кладём" {
                        eprintln!("{id}: {err}");
                    }
                }
            }
            if let Err(err) = node.expire(24 * 60 * 60 * 1000) {
                eprintln!("льгота: {err}");
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }
    loop {
        if let Err(err) = node.expire(24 * 60 * 60 * 1000) {
            eprintln!("льгота: {err}");
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

fn ctl(args: Vec<String>) {
    let mut data = default_data();
    let mut i = 0;
    let mut rest = Vec::new();
    while i < args.len() {
        if args[i] == "--data" {
            data = PathBuf::from(args.get(i + 1).cloned().unwrap_or_default());
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    if rest.is_empty() {
        eprintln!("нужна команда: status, files, chats, dial, put, chat");
        std::process::exit(2);
    }
    let port_text = std::fs::read_to_string(data.join("control.port")).unwrap_or_else(|_| {
        eprintln!("нода не запущена: нет control.port в {}", data.display());
        std::process::exit(1);
    });
    let port: u16 = port_text.trim().parse().unwrap_or_else(|_| {
        eprintln!("битый control.port");
        std::process::exit(1);
    });
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|err| {
        eprintln!("нет связи с нодой на 127.0.0.1:{port}: {err}");
        std::process::exit(1);
    });
    let line = rest.join(" ");
    use std::io::{Read, Write};
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.write_all(b"\n");
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    print!("{buf}");
    if !buf.ends_with('\n') {
        println!();
    }
    append_log(&data, &format!("ctl {line} -> {}", buf.trim()));
    if buf.starts_with("err") {
        std::process::exit(1);
    }
}

fn contact_port(contact: &str) -> String {
    contact.rsplit(':').next().unwrap_or("?").to_string()
}

fn lan_ipv4() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("192.0.2.1:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        None
    } else {
        Some(ip.to_string())
    }
}

fn append_log(dir: &std::path::Path, text: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("node.log")) {
        let _ = writeln!(file, "{text}");
    }
}

fn default_data() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".nexxus-rs")
}

fn parse_socks(value: Option<&str>) -> Result<(String, u16), String> {
    let raw = value.unwrap_or("").trim();
    if raw.is_empty() {
        return Err("Не задан Tor SOCKS.".into());
    }
    let Some((host, port_text)) = raw.rsplit_once(':') else {
        return Err("Tor SOCKS задаётся как host:port.".into());
    };
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err("Tor SOCKS задаётся как host:port.".into());
    }
    let port: u16 = port_text.parse().map_err(|_| "Некорректный порт SOCKS.".to_string())?;
    if port == 0 {
        return Err("Некорректный порт SOCKS.".into());
    }
    Ok((host.to_string(), port))
}
