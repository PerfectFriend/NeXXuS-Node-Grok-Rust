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
        Some(other) => {
            eprintln!("неизвестная команда: {other}");
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "NeXXXUs Rust 0.1.0\n\n\
         nexxus start [--data DIR] [--port N] [--name NAME] [--mnemonic \"12 слов\"] [--contact URI]\n\
         [--profile lab|onion] [--tor-bin PATH] [--tor-socks ХОСТ:ПОРТ] [--advertise ХОСТ]\n\n\
         Лабораторный TCP на 127.0.0.1. Сейф map.bin, до трёх копий, проверка чанка.\n\
         Профиль onion запускает бинарник tor и берёт адрес только из его hostname.\n\
         Нет бинарника и нет готового v3 — старт с ошибкой. Адрес не выдумывается."
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
        (advertise.unwrap_or_else(|| "127.0.0.1".into()), None)
    } else {
        eprintln!("Профиль только lab или onion.");
        std::process::exit(2);
    };
    let socks_ref = socks.as_ref().map(|(host, port)| (host.as_str(), *port));
    let node = Node::start_with(&data, account.identity, account.device_id, &name, port, &advertise_host, &profile, socks_ref).unwrap_or_else(|e| {
        eprintln!("не поднялась: {e}");
        std::process::exit(1);
    });
    let _hold_tor = tor_guard;
    println!("Каталог: {}", data.display());
    println!("Контакт: {}", node.contact());
    println!("Файлов в сейфе: {}. Слушаю 127.0.0.1:{port}.", node.file_ids().len());
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
