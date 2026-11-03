use nexxus_crypto::{
    derive_session_key, ed25519_verify, fingerprint_from_pub, format_contact, open_packed,
    parse_contact, seal, x25519_public, x25519_shared, Hello, Identity,
};

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

fn hex24(text: &str) -> [u8; 24] {
    hex::decode(text).unwrap().try_into().unwrap()
}

#[test]
fn rfc7748_shared_secret() {
    let alice = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    assert_eq!(
        hex::encode(x25519_public(&alice)),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(x25519_public(&bob)),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    let shared = x25519_shared(&alice, &x25519_public(&bob)).unwrap();
    assert_eq!(
        hex::encode(shared),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
    assert!(x25519_shared(&alice, &[0u8; 32]).is_err());
}

#[test]
fn linux_vectors() {
    let raw = include_str!("../../../vectors/nxx-vectors.json");
    let vec: serde_json::Value = serde_json::from_str(raw).unwrap();
    let id = Identity::from_mnemonic(vec["phrase"].as_str().unwrap()).unwrap();
    let id2 = Identity::from_mnemonic(vec["phrase2"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(id.seed), vec["seed"].as_str().unwrap());
    assert_eq!(hex::encode(id.x_priv), vec["xPriv"].as_str().unwrap());
    assert_eq!(hex::encode(id.x_pub), vec["xPub"].as_str().unwrap());
    assert_eq!(hex::encode(id.ed_priv), vec["edPriv"].as_str().unwrap());
    assert_eq!(hex::encode(id.ed_pub), vec["edPub"].as_str().unwrap());
    assert_eq!(hex::encode(id.vault_key), vec["vault"].as_str().unwrap());
    assert_eq!(id.fingerprint(), vec["fp"].as_str().unwrap());
    assert_eq!(id.fingerprint(), fingerprint_from_pub(&id.x_pub));
    assert_eq!(id2.fingerprint(), vec["fp2"].as_str().unwrap());
    assert_eq!(hex::encode(x25519_public(&hex32(vec["ephPriv"].as_str().unwrap()))), vec["ephPub"].as_str().unwrap());

    let hello = Hello::sign(&id, vec["ephPub"].as_str().unwrap(), "alpha", "10.0.0.8", 4377);
    hello.verify().unwrap();
    assert_eq!(hello.signature_hex, vec["hello"]["sig"].as_str().unwrap());
    let mut tampered = hello.clone();
    tampered.host = "evil.example".to_string();
    assert!(tampered.verify().is_err());

    let session = derive_session_key(
        &id.x_priv,
        &id.x_pub,
        &hex32(vec["ephPriv"].as_str().unwrap()),
        &id2.x_pub,
        &hex32(vec["ephPub2"].as_str().unwrap()),
        true,
    )
    .unwrap();
    let back = derive_session_key(
        &id2.x_priv,
        &id2.x_pub,
        &hex32(vec["ephPriv2"].as_str().unwrap()),
        &id.x_pub,
        &hex32(vec["ephPub"].as_str().unwrap()),
        false,
    )
    .unwrap();
    assert_eq!(hex::encode(session), vec["session"].as_str().unwrap());
    assert_eq!(session, back);

    let ct = seal(&session, &hex24(vec["fixedNonce"].as_str().unwrap()), "привет-nexxus".as_bytes()).unwrap();
    assert_eq!(hex::encode(&ct), vec["fixedCt"].as_str().unwrap());
    let packed = hex::decode(vec["aead"].as_str().unwrap()).unwrap();
    let plain = open_packed(&session, &packed).unwrap();
    assert_eq!(String::from_utf8(plain).unwrap(), "привет-nexxus");
    assert!(ed25519_verify(&id.ed_pub, b"no", &hex::decode(hello.signature_hex.clone()).unwrap().try_into().unwrap()) == false);

    let contact = format_contact(&nexxus_crypto::Contact {
        fingerprint: id.fingerprint(),
        public_hex: id.pub_hex(),
        host: "10.0.0.8".to_string(),
        port: 4377,
    });
    assert_eq!(parse_contact(&contact).unwrap().fingerprint, id.fingerprint());
    let mixed = format!("nexxus:1:{}:{}@127.0.0.1:4377", id2.fingerprint(), id.pub_hex());
    assert!(parse_contact(&mixed).is_err());
}
