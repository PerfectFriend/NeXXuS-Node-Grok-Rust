use std::path::PathBuf;
use std::time::Duration;

use nexxus_node::{load_account, Node};

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
         nexxus start [--data DIR] [--port N] [--name NAME] [--mnemonic \"12 слов\"] [--contact URI]\n\n\
         Лабораторный TCP на 127.0.0.1. Сейф map.bin, до трёх копий, проверка чанка.\n\
         Tor ещё нет. Фраза пишется в identity.bin под machine.key и второй раз не печатается."
    );
}

fn start(args: Vec<String>) {
    let mut port = 4377u16;
    let mut name = "rust".to_string();
    let mut mnemonic = None;
    let mut contact = None;
    let mut data = default_data();
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
    let node = Node::start(&data, account.identity, account.device_id, &name, port).unwrap_or_else(|e| {
        eprintln!("не поднялась: {e}");
        std::process::exit(1);
    });
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
