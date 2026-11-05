use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use nexxus_node::load_account;

#[test]
fn linux_opens_rust_identity_bin() {
    let dir = std::env::temp_dir().join(format!("nxx-id-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let first = load_account(&dir, Some(phrase)).unwrap();
    assert!(first.fresh_words.is_some());
    let again = load_account(&dir, None).unwrap();
    assert!(again.fresh_words.is_none());
    assert_eq!(again.identity.fingerprint(), first.identity.fingerprint());
    let Some(js) = std::env::var("NEXXUS_JS_DIR").ok() else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let mut child = Command::new("node")
        .current_dir(&js)
        .arg("--input-type=module")
        .arg("-e")
        .arg(JS)
        .arg(dir.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let line = BufReader::new(stdout).lines().next().unwrap().unwrap();
    let status = child.wait().unwrap();
    assert!(status.success(), "{line}");
    assert_eq!(line, first.identity.fingerprint());
    let _ = std::fs::remove_dir_all(&dir);
}

const JS: &str = r#"
import { readFile } from "node:fs/promises";
import { decrypt } from "./lib/crypto-io.mjs";
const dir = process.argv[1];
const key = new Uint8Array(await readFile(dir + "/machine.key"));
const packed = new Uint8Array(await readFile(dir + "/identity.bin"));
const saved = JSON.parse(new TextDecoder().decode(decrypt(key, packed)));
if (!saved.mnemonic || !saved.deviceId) throw new Error("битый identity.bin");
console.log(saved.fingerprint);
"#;
