use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexxus_crypto::Identity;
use nexxus_net::Mesh;

#[test]
fn chat_with_linux_node() {
    let Some(dir) = std::env::var("NEXXUS_JS_DIR").ok() else {
        eprintln!("skip: задайте NEXXUS_JS_DIR, чтобы сверить канал с Linux-нодой");
        return;
    };
    let rust = Mesh::listen(
        Identity::from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap(),
        "rust",
        "127.0.0.1",
        0,
    )
    .unwrap();
    let mut child = Command::new("node")
        .current_dir(&dir)
        .arg("--input-type=module")
        .arg("-e")
        .arg(JS)
        .arg(rust.contact())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node");
    let stdout = child.stdout.take().unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let bucket = lines.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            bucket.lock().expect("lines").push(line);
        }
    });
    let js_contact = wait_line(&lines, "JS_CONTACT ", Duration::from_secs(8)).expect("Linux-нода не назвала контакт");
    let fp = js_contact.split(':').nth(2).unwrap().to_string();
    assert!(rust.wait_chat("из js", Duration::from_secs(5)), "сообщение Linux не дошло");
    assert!(rust.send_chat(&fp, "из rust").is_ok());
    assert!(wait_exact(&lines, "JS_GOT", Duration::from_secs(5)), "Linux не увидел ответ");
    let status = child.wait().expect("wait");
    if !status.success() {
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).ok();
        panic!("linux node failed: {status}\n{err}");
    }
}

fn wait_line(lines: &Arc<Mutex<Vec<String>>>, prefix: &str, timeout: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(line) = lines.lock().expect("lines").iter().find(|line| line.starts_with(prefix)) {
            return Some(line[prefix.len()..].to_string());
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    None
}

fn wait_exact(lines: &Arc<Mutex<Vec<String>>>, text: &str, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if lines.lock().expect("lines").iter().any(|line| line == text) {
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
const data = await mkdtemp(path.join(os.tmpdir(), "nxx-rs-"));
const node = await createNode({
  data, port: 19341, http: 19342, host: "127.0.0.1", advertise: "127.0.0.1", name: "js",
});
console.log("JS_CONTACT " + node.contact);
await node.addContact(rust);
const fp = rust.split(":")[2];
for (let i = 0; i < 50 && !node.snapshot().contacts.some((c) => c.online); i++) {
  await new Promise((resolve) => setTimeout(resolve, 100));
}
if (!node.snapshot().contacts.some((c) => c.online)) {
  console.error(node.snapshot().log.map((line) => line.text).join("\n"));
  process.exit(2);
}
node.sendChat(fp, "из js");
const deadline = Date.now() + 5000;
while (Date.now() < deadline) {
  if (node.snapshot().messages.some((m) => m.text === "из rust")) {
    console.log("JS_GOT");
    await node.stop();
    await rm(data, { recursive: true, force: true });
    process.exit(0);
  }
  await new Promise((resolve) => setTimeout(resolve, 50));
}
console.error(node.snapshot().log.map((line) => line.text).join("\n"));
process.exit(3);
"#;
