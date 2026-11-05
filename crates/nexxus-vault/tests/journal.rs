use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::time::Duration;

use nexxus_crypto::Identity;
use nexxus_vault::{canon, open_chunk, seal_chunk, Store};

const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const DEVICE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[test]
fn canon_matches_sorted_json() {
    let value = serde_json::json!({"b": 1, "a": {"d": true, "c": "x"}});
    assert_eq!(canon(&value), r#"{"a":{"c":"x","d":true},"b":1}"#);
}

#[test]
fn local_file_roundtrip() {
    let dir = std::env::temp_dir().join(format!("nxx-vault-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let identity = Identity::from_mnemonic(PHRASE).unwrap();
    let mut store = Store::create(&dir, identity.clone(), DEVICE).unwrap();
    let mut bytes = vec![0u8; 20 * 1024];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    bytes[..12].copy_from_slice(b"nexxus-vault");
    let rec = store.add_file("file-1", "blob.bin", &bytes).unwrap();
    assert_eq!(rec.chunks.len(), 2);
    let opened = Store::open(&dir, identity, DEVICE).unwrap().read_file("file-1").unwrap();
    assert_eq!(opened, bytes);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn chunk_nonce_changes_ciphertext() {
    let key = [7u8; 32];
    let prefix = [9u8; 16];
    let padded = nexxus_vault::pad_chunk(b"same");
    let (a, ct_a) = seal_chunk(&key, &padded, &prefix, 0, 0).unwrap();
    let (b, ct_b) = seal_chunk(&key, &padded, &prefix, 0, 1).unwrap();
    assert_ne!(a, b);
    assert_ne!(ct_a, ct_b);
    assert_eq!(open_chunk(&key, &ct_b, &hex::encode(prefix), 0, 1).unwrap(), padded);
}

#[test]
fn pin_then_grace_then_proof() {
    let dir = std::env::temp_dir().join(format!("nxx-grace-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let identity = Identity::from_mnemonic(PHRASE).unwrap();
    let mut store = Store::create(&dir, identity, DEVICE).unwrap();
    store.add_file("f", "a.txt", b"grace").unwrap();
    let planned = store.plan_replica("f", 1).unwrap();
    let holder = nexxus_vault::Holder {
        fingerprint: "nxx1holder".into(),
        host: "127.0.0.1".into(),
        port: 1,
        pub_hex: "ab".into(),
    };
    store.pin_replica("f", &planned, &holder, 1_000).unwrap();
    assert_eq!(store.stale_replicas(100, 1_200).unwrap().len(), 1);
    let proof = store.proof_for("f", 1, 0, b"challenge-bytes").unwrap();
    assert_eq!(proof.len(), 64);
    store.note_seen("f", 1, 2_000).unwrap();
    assert!(store.stale_replicas(100, 2_050).unwrap().is_empty());
    store.unpin_replica("f", 1, 3_000).unwrap();
    assert!(store.files().unwrap()[0].replicas.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn linux_node_reads_rust_journal_and_rust_reads_linux() {
    let Some(dir_js) = std::env::var("NEXXUS_JS_DIR").ok() else {
        eprintln!("skip: задайте NEXXUS_JS_DIR");
        return;
    };
    let root = std::env::temp_dir().join(format!("nxx-map-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let rust_dir = root.join("rust");
    let js_dir = root.join("js");
    fs::create_dir_all(&js_dir).unwrap();
    let identity = Identity::from_mnemonic(PHRASE).unwrap();
    let mut store = Store::create(&rust_dir, identity.clone(), DEVICE).unwrap();
    store.add_file("from-rust", "rust.txt", b"from-rust-vault").unwrap();

    let mut child = Command::new("node")
        .current_dir(&dir_js)
        .arg("--input-type=module")
        .arg("-e")
        .arg(JS)
        .arg(rust_dir.to_str().unwrap())
        .arg(js_dir.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let bucket = lines.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            bucket.lock().unwrap().push(line);
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    let mut saw = false;
    while std::time::Instant::now() < deadline {
        if lines.lock().unwrap().iter().any(|line| line == "RUST_OK from-rust-vault") {
            saw = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    let status = child.wait().unwrap();
    if !status.success() || !saw {
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).ok();
        panic!("linux journal failed\n{err}");
    }
    let js_store = Store::open(&js_dir, identity, DEVICE).unwrap();
    let files = js_store.files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(js_store.read_file(&files[0].id).unwrap(), b"from-linux-vault");
    let _ = fs::remove_dir_all(&root);
}

const JS: &str = r#"
import { readFile } from "node:fs/promises";
import { deriveIdentity } from "./lib/identity.mjs";
import { decrypt } from "./lib/crypto-io.mjs";
import { foldJournal, openChunk } from "./lib/vault.mjs";
import { createNode } from "./lib/node.mjs";

const phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";
const rustDir = process.argv[1];
const jsDir = process.argv[2];
const identity = deriveIdentity(phrase);
const packed = new Uint8Array(await readFile(rustDir + "/map.bin"));
const journal = JSON.parse(new TextDecoder().decode(decrypt(identity.vaultKey, packed)));
const files = foldJournal(journal, identity.edPub);
if (files.size !== 1) throw new Error("files " + files.size);
const file = [...files.values()][0];
const { readFileSync } = await import("node:fs");
const key = Buffer.from(file.fileKey, "hex");
let out = Buffer.alloc(0);
for (let i = 0; i < file.chunks.length; i++) {
  const cid = file.chunks[i];
  const ct = readFileSync(rustDir + "/blobs/" + cid.slice(0, 2) + "/" + cid);
  const padded = openChunk(key, ct, file.localPrefix, i, 0);
  const take = i === file.chunks.length - 1 ? file.size - i * 16384 : 16384;
  out = Buffer.concat([out, Buffer.from(padded.subarray(0, take))]);
}
if (out.toString() !== "from-rust-vault") throw new Error("rust bytes " + out.toString());
console.log("RUST_OK " + out.toString());

const node = await createNode({
  data: jsDir,
  port: 19521,
  http: 19522,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "js-vault",
  mnemonic: phrase,
});
await node.storePlainFile({ name: "js.txt", bytes: Buffer.from("from-linux-vault") });
await node.stop();
"#;
