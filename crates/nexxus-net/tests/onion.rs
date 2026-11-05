use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use nexxus_crypto::Identity;
use nexxus_net::Mesh;

#[test]
fn lab_refuses_onion_and_onion_dials_through_socks() {
    let onion = format!("{}.onion", "a".repeat(56));
    let listener = Mesh::listen(
        Identity::from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow").unwrap(),
        "lab",
        "127.0.0.1",
        0,
    )
    .unwrap();
    let caller = Mesh::listen(
        Identity::from_mnemonic("letter advice cage absurd amount doctor acoustic avoid letter advice cage above").unwrap(),
        "onion",
        &onion,
        0,
    )
    .unwrap();
    let direct = caller.dial(&listener.contact().replace("127.0.0.1", &onion));
    assert!(direct.unwrap_err().contains("--profile onion"), "лабораторный профиль не должен звонить на onion");
    let port = listener.port();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen_bg = seen.clone();
    let socks = TcpListener::bind("127.0.0.1:0").unwrap();
    let socks_port = socks.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut client, _) = socks.accept().unwrap();
        let mut hello = [0u8; 3];
        client.read_exact(&mut hello).unwrap();
        client.write_all(&[5, 0]).unwrap();
        let mut head = [0u8; 5];
        client.read_exact(&mut head).unwrap();
        let mut name = vec![0u8; head[4] as usize];
        client.read_exact(&mut name).unwrap();
        let mut port_buf = [0u8; 2];
        client.read_exact(&mut port_buf).unwrap();
        *seen_bg.lock().unwrap() = String::from_utf8(name).unwrap();
        let target = u16::from_be_bytes(port_buf);
        let mut backend = TcpStream::connect(("127.0.0.1", target)).unwrap();
        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut from_client = client.try_clone().unwrap();
        let mut to_backend = backend.try_clone().unwrap();
        thread::spawn(move || {
            let _ = std::io::copy(&mut from_client, &mut to_backend);
        });
        thread::spawn(move || {
            let _ = std::io::copy(&mut backend, &mut client);
        });
        let _ = port;
    });
    caller.set_route("onion", Some(("127.0.0.1", socks_port))).unwrap();
    let uri = listener.contact().replace("127.0.0.1", &onion);
    caller.dial(&uri).unwrap();
    let mut sent = false;
    for _ in 0..50 {
        if caller.send_chat(&fp_of(&listener), "через socks").is_ok() {
            sent = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(sent, "канал через SOCKS не поднялся");
    assert!(listener.wait_chat("через socks", Duration::from_secs(3)));
    assert_eq!(seen.lock().unwrap().as_str(), onion);
}

fn fp_of(mesh: &Mesh) -> String {
    mesh.contact().split(':').nth(2).unwrap().to_string()
}
