use nexxus_crypto::Identity;
use nexxus_wire::{open_queue, pack_xftp, seal_queue_with, unpack_xftp, verify_desc, Sealed};

#[test]
fn linux_vector_opens() {
    let raw = include_str!("../../../vectors/smp-xftp.json");
    let value: serde_json::Value = serde_json::from_str(raw).unwrap();
    let recip = [0x11u8; 32];
    let eph = [0x22u8; 32];
    let nonce = [0x33u8; 24];
    let sealed = seal_queue_with(
        &eph,
        &hex::decode(value["smp"]["ephPub"].as_str().unwrap()).unwrap().try_into().unwrap(),
        &hex::decode(value["smp"]["recipPub"].as_str().unwrap()).unwrap().try_into().unwrap(),
        &nonce,
        "секрет очереди".as_bytes(),
    )
    .unwrap();
    assert_eq!(sealed.ct, value["smp"]["ct"].as_str().unwrap());
    let plain = open_queue(
        &recip,
        &Sealed {
            eph: value["smp"]["ephPub"].as_str().unwrap().into(),
            nonce: hex::encode(nonce),
            ct: value["smp"]["ct"].as_str().unwrap().into(),
        },
    )
    .unwrap();
    assert_eq!(plain, "секрет очереди".as_bytes());
    let desc = &value["xftp"]["desc"];
    assert!(verify_desc(desc));
    let mut with_host = desc.clone();
    with_host["host"] = serde_json::json!("127.0.0.1");
    assert!(!verify_desc(&with_host));
    let bodies: Vec<Vec<u8>> = value["xftp"]["bodies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| hex::decode(item.as_str().unwrap()).unwrap())
        .collect();
    let bytes = unpack_xftp(desc, &bodies).unwrap();
    assert_eq!(bytes, b"xftp-without-addresses");
    let id = Identity::from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow").unwrap();
    let (packed, _) = pack_xftp("pack.bin", b"xftp-without-addresses", &id).unwrap();
    assert!(packed.get("host").is_none());
    assert!(verify_desc(&packed));
}
