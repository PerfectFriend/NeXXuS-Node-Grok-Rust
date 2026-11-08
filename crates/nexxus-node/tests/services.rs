use std::fs;
use std::time::Duration;

use nexxus_crypto::Identity;
use nexxus_node::Node;

fn node(dir: &std::path::Path, phrase: &str, name: &str) -> Node {
    Node::start(dir, Identity::from_mnemonic(phrase).unwrap(), [9u8; 16], name, 0).unwrap()
}

fn fp(node: &Node) -> String {
    node.contact().split(':').nth(2).unwrap().to_string()
}

#[test]
fn queue_hides_text_and_refuses_a_stranger() {
    let root = std::env::temp_dir().join(format!("nxx-smp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let relay = node(&root.join("relay"), "legal winner thank year wave sausage worth useful legal winner thank yellow", "relay");
    let alice = node(&root.join("alice"), "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "alice");
    let bob = node(&root.join("bob"), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "bob");
    alice.dial(&relay.contact()).unwrap();
    bob.dial(&relay.contact()).unwrap();
    assert!(alice.wait_peer(&fp(&relay), Duration::from_secs(3)));
    assert!(bob.wait_peer(&fp(&relay), Duration::from_secs(3)));
    let inbox = alice.open_inbox(&fp(&relay)).unwrap();
    let pub_key: [u8; 32] = hex::decode(&inbox.pub_hex).unwrap().try_into().unwrap();
    bob.send_sealed(&fp(&relay), &inbox.id, &pub_key, "секрет очереди".as_bytes()).unwrap();
    let stored = fs::read_to_string(root.join("relay").join("smp.json")).unwrap();
    assert!(!stored.contains("секрет"), "{stored}");
    let (owner, dumped) = relay.queue_record(&inbox.id).unwrap();
    assert_eq!(owner, fp(&alice));
    assert!(!dumped.contains("секрет"));
    let denied = bob.pull_sealed(&fp(&relay), &inbox.id, &inbox.priv_key).unwrap_err();
    assert!(denied.contains("не ответила"), "{denied}");
    let got = alice.pull_sealed(&fp(&relay), &inbox.id, &inbox.priv_key).unwrap();
    assert_eq!(got, vec!["секрет очереди".as_bytes()]);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn xftp_description_has_no_address() {
    let root = std::env::temp_dir().join(format!("nxx-xftp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let a = node(&root.join("a"), "legal winner thank year wave sausage worth useful legal winner thank yellow", "xa");
    let b = node(&root.join("b"), "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "xb");
    a.dial(&b.contact()).unwrap();
    assert!(a.wait_peer(&fp(&b), Duration::from_secs(3)));
    assert!(b.wait_peer(&fp(&a), Duration::from_secs(3)));
    let desc = a.xftp_send(&fp(&b), "pack.bin", b"xftp-without-addresses").unwrap();
    assert!(desc.get("host").is_none() && desc.get("port").is_none());
    let mut found = None;
    for _ in 0..50 {
        found = b.named_files().into_iter().find(|(_, name, _)| name == "pack.bin");
        if found.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let (id, _, _) = found.expect("описание не собралось");
    assert_eq!(b.read_bytes(&id).unwrap(), b"xftp-without-addresses");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn miner_keeps_its_own_file() {
    let root = std::env::temp_dir().join(format!("nxx-miner-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let miner = node(&root.join("miner"), "legal winner thank year wave sausage worth useful legal winner thank yellow", "miner");
    let user = node(&root.join("user"), "letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "user");
    miner.enable_miner();
    user.dial(&miner.contact()).unwrap();
    assert!(user.wait_peer(&fp(&miner), Duration::from_secs(3)));
    let mut supply = None;
    for _ in 0..50 {
        supply = user.miner_supply(&fp(&miner));
        if supply.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(supply.unwrap_or(0) > 0);
    let own = miner.store_bytes("rent.bin", b"not-free").unwrap();
    miner.replicate_to(&own, &user.contact()).unwrap();
    assert_eq!(miner.copies(&own), 0);
    let shared = user.store_bytes("keep.bin", b"user-file").unwrap();
    user.replicate_to(&shared, &miner.contact()).unwrap();
    assert!(user.copies(&shared) >= 1);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn drive_folder_is_plaintext() {
    let root = std::env::temp_dir().join(format!("nxx-drive-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let node = node(&root, "legal winner thank year wave sausage worth useful legal winner thank yellow", "drive");
    let drive = root.join("drive");
    fs::create_dir_all(&drive).unwrap();
    fs::write(drive.join("note.txt"), b"hello-drive").unwrap();
    node.sync_drive().unwrap();
    let rec = node.named_files().into_iter().find(|(_, name, _)| name == "note.txt").expect("нет в сейфе");
    assert_eq!(node.read_bytes(&rec.0).unwrap(), b"hello-drive");
    fs::write(drive.join("note.txt"), b"hello-edited").unwrap();
    node.sync_drive().unwrap();
    let edited: Vec<_> = node.named_files().into_iter().filter(|(_, name, _)| name == "note.txt").collect();
    assert_eq!(edited.len(), 1);
    assert_eq!(node.read_bytes(&edited[0].0).unwrap(), b"hello-edited");
    fs::remove_file(drive.join("note.txt")).unwrap();
    node.sync_drive().unwrap();
    assert!(node.named_files().iter().all(|(_, name, _)| name != "note.txt"));
    node.store_bytes("from-net.txt", b"out").unwrap();
    node.sync_drive().unwrap();
    assert_eq!(fs::read(drive.join("from-net.txt")).unwrap(), b"out");
    let _ = fs::remove_dir_all(&root);
}
