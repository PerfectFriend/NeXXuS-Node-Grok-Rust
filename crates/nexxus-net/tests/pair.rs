use std::time::Duration;

use nexxus_crypto::Identity;
use nexxus_net::Mesh;

#[test]
fn two_rust_nodes_chat() {
    let a = Mesh::listen(
        Identity::from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap(),
        "rust-a",
        "127.0.0.1",
        0,
    )
    .unwrap();
    let b = Mesh::listen(
        Identity::from_mnemonic(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        )
        .unwrap(),
        "rust-b",
        "127.0.0.1",
        0,
    )
    .unwrap();
    b.dial(&a.contact()).unwrap();
    let mut linked = false;
    for _ in 0..50 {
        if b.send_chat(&a_fp(&a), "из b").is_ok() {
            linked = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(linked, "канал не поднялся");
    assert!(a.wait_chat("из b", Duration::from_secs(3)));
    assert!(a.send_chat(&b_fp(&b), "из a").is_ok());
    assert!(b.wait_chat("из a", Duration::from_secs(3)));
}

fn a_fp(mesh: &Mesh) -> String {
    mesh.contact().split(':').nth(2).unwrap().to_string()
}

fn b_fp(mesh: &Mesh) -> String {
    mesh.contact().split(':').nth(2).unwrap().to_string()
}
