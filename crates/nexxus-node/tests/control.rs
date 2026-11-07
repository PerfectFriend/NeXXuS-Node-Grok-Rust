use std::fs;

use nexxus_crypto::Identity;
use nexxus_node::Node;

#[test]
fn local_control_stores_a_file() {
    let dir = std::env::temp_dir().join(format!("nxx-ctl-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let node = Node::start(
        &dir,
        Identity::from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow").unwrap(),
        [2u8; 16],
        "ctl",
        0,
    )
    .unwrap();
    let path = dir.join("hello.txt");
    fs::write(&path, b"lab-file").unwrap();
    let stored = node.command(&format!("put {}", path.display()));
    assert!(stored.starts_with("ok "), "{stored}");
    assert!(node.command("files").contains("copies=0"));
    assert!(node.command("status").contains("files=1"));
    let port = node.serve_control(0).unwrap();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    use std::io::{Read, Write};
    stream.write_all(b"contact\n").unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("nexxus:1:"), "{buf}");
    let _ = fs::remove_dir_all(&dir);
}
