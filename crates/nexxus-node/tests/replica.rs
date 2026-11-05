use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexxus_crypto::Identity;
use nexxus_node::Node;

const RUST_PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const DEVICE: [u8; 16] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];

#[test]
fn replicas_and_audit_with_linux() {
    let Some(js) = std::env::var("NEXXUS_JS_DIR").ok() else {
        eprintln!("skip: задайте NEXXUS_JS_DIR");
        return;
    };
    let dir = std::env::temp_dir().join(format!("nxx-rep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let identity = Identity::from_mnemonic(RUST_PHRASE).unwrap();
    let node = Node::start(&dir, identity, DEVICE, "rust-vault", 0).unwrap();
    node.add_file("rust-file", "rust.txt", b"rust-replica").unwrap();

    let mut child = Command::new("node")
        .current_dir(&js)
        .arg("--input-type=module")
        .arg("-e")
        .arg(JS)
        .arg(node.contact())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let bucket = lines.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            bucket.lock().unwrap().push(line);
        }
    });
    let js_contact = wait_prefix(&lines, "JS_CONTACT ", Duration::from_secs(8)).expect("нет контакта Linux");
    let fp = js_contact.split(':').nth(2).unwrap().to_string();
    assert!(node.wait_peer(&fp, Duration::from_secs(5)), "Linux не открыл канал");
    assert!(wait_prefix(&lines, "LINUX_COPIES ", Duration::from_secs(8)).is_some(), "Linux не положил копию");
    node.replicate_to("rust-file", &js_contact).expect("копия на Linux");
    assert_eq!(node.copies("rust-file"), 1);
    assert!(node.audit_holder("rust-file").expect("проверка"), "Linux не подтвердил чанк");
    assert_eq!(node.copies("rust-file"), 1);
    node.send_chat(&fp, "rust-audited").unwrap();
    assert!(wait_exact(&lines, "AUDIT_KEPT", Duration::from_secs(8)), "Linux снял свою копию");
    let status = child.wait().unwrap();
    if !status.success() {
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).ok();
        panic!("{status}\n{err}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn wait_prefix(lines: &Arc<Mutex<Vec<String>>>, prefix: &str, timeout: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(line) = lines.lock().unwrap().iter().find(|line| line.starts_with(prefix)) {
            return Some(line[prefix.len()..].to_string());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    None
}

fn wait_exact(lines: &Arc<Mutex<Vec<String>>>, text: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if lines.lock().unwrap().iter().any(|line| line == text) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    false
}

const JS: &str = r#"
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";
const rust = process.argv[1];
const phrase = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
const data = await mkdtemp(path.join(os.tmpdir(), "nxx-js-rep-"));
const node = await createNode({
  data, port: 19631, http: 19632, host: "127.0.0.1", advertise: "127.0.0.1", name: "js-rep", mnemonic: phrase,
});
console.log("JS_CONTACT " + node.contact);
await node.storePlainFile({ name: "linux.txt", bytes: Buffer.from("linux-replica") });
await node.addContact(rust);
for (let i = 0; i < 80 && !(node.snapshot().files[0] && node.snapshot().files[0].copies >= 1); i++) {
  await new Promise((resolve) => setTimeout(resolve, 100));
}
const copies = node.snapshot().files[0] ? node.snapshot().files[0].copies : 0;
if (copies < 1) {
  console.error(node.snapshot().log.map((line) => line.text).join("\n"));
  process.exit(2);
}
console.log("LINUX_COPIES " + copies);
for (let i = 0; i < 80 && !node.snapshot().messages.some((m) => m.text === "rust-audited"); i++) {
  await new Promise((resolve) => setTimeout(resolve, 100));
}
if (!node.snapshot().messages.some((m) => m.text === "rust-audited")) {
  console.error("нет сигнала rust");
  process.exit(4);
}
await node.auditNow();
const after = node.snapshot().files[0].copies;
if (after < 1) {
  console.error(node.snapshot().log.map((line) => line.text).join("\n"));
  process.exit(3);
}
console.log("AUDIT_KEPT");
await node.stop();
await rm(data, { recursive: true, force: true });
"#;
