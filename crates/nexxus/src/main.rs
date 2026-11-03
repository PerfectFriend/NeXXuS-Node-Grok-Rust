use nexxus_crypto::Identity;
use nexxus_net::Mesh;

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
         nexxus start [--port N] [--name NAME] [--mnemonic \"12 слов\"]\n\n\
         Лабораторный TCP: HELLO v3, чат. Сейфа, копий и Tor ещё нет.\n\
         Фраза печатается один раз и на диск не пишется."
    );
}

fn start(args: Vec<String>) {
    let mut port = 4377u16;
    let mut name = "rust".to_string();
    let mut mnemonic = None;
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
            other => {
                eprintln!("неизвестный аргумент: {other}");
                std::process::exit(2);
            }
        }
    }
    let (identity, fresh) = match mnemonic {
        Some(words) => (Identity::from_mnemonic(&words).expect("фраза"), false),
        None => {
            let words = nexxus_crypto::create_mnemonic().expect("фраза");
            println!("Фраза (запишите, больше не покажется):\n{words}\n");
            (Identity::from_mnemonic(&words).expect("новая фраза"), true)
        }
    };
    let _ = fresh;
    let mesh = Mesh::listen(identity, &name, "127.0.0.1", port).expect("порт занят");
    println!("Контакт: {}", mesh.contact());
    println!("Слушаю 127.0.0.1:{}. Сейфа нет. Выход — Ctrl-C.", mesh.port());
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
