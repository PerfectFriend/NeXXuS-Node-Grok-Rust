# NeXXuS

**English** · [Español](README.es.md) · [Русский](README.md)

![NeXXuS: leaving the grey city for a living network](docs/banner.jpg)

NeXXuS is a foundation for a different internet. Not a faster one, and not a more convenient one on the first day. Different in kind: no owner in the middle, no mandatory data center, and no disk that can be switched off by a single decision.

The old internet stays where it is convenient. This one is for the case when a secret must not live inside one company, and an old phone on a charger is a node rather than waste.

This repository is the Rust node. The protocol reference is still [NeXXXUs-Grok](https://github.com/PerfectFriend/NeXXXUs-Grok), Linux 0.10.0. Rust does not replace it until it passes the same trials. The port plan is [docs/MIGRATION.md](docs/MIGRATION.md).

## Why it exists

A normal cloud stores the whole file with whoever you pay. They see metadata, they can refuse access, and the archive disappears with them if they decide so.

NeXXuS cuts a file into 16 KiB pieces. Each piece is encrypted on its own. The network does not store a file as a file. It stores mute ciphertext. Only the holder of the map can assemble it. The map lives in the owner's journal, not on a public board.

A node is not a machine in a rack. It is an old phone, a home computer, or a small box that was wiped, left online, and left on power. A person gives the disk room. In return the network leaves them a personal share they do not have to rent from someone else's host.

## How a node is shaped

1. Twelve BIP39 words. They derive the link keys, the signing key, and the vault key. The phrase is shown once.
2. Several devices may live on one key. To the journal that is one household, not a crowd of strangers.
3. Space for the network is taken in 16 GiB sections, and only when at least that much is free. Less than that, and the node does not become storage.
4. The owner keeps one eighth of the space they gave. That is the vault: secrets, and whatever they agreed to hold. The rest is held by the network, not by them personally.
5. A piece does not sit as three copies on one shelf. The copies go to different nodes. Each copy has its own nonce, so the ciphertexts differ byte for byte. One copy cannot be swapped in for another.
6. The owner's node keeps their own encrypted copy. The network keeps three more. One foreign disk dying does not erase the file.
7. If a node goes quiet, nothing is dropped for 24 hours. That is time to charge the phone, change networks, or raise the same key on another machine. Silence longer than a day moves the copies to nodes that still answer. Thirty days without a break raises the local rating.
8. Rating and penalty are remembered by the node that caught the failure or the substitution. There is no global blacklist. That would be a new center.
9. A swapped chunk is visible without opening the file. The identifier is the hash of the ciphertext. The question "prove this piece is still the same" can be answered only if those exact bytes are on disk.
10. An external disk can be added to the node. More space given means a larger personal share.
11. Space beyond that share is not taken "from the cloud". It is taken from nodes that hold other people's pieces. Payment is not checked in this version and is not part of the protocol yet.
12. Apple is a client only. There is no storage node on iOS. The system does not give a phone away to permanent background storage.

## What this node already does

Build **0.2.0-lab**. It matches Linux 0.10.0 on:

- the twelve words, the `nxx1` fingerprint, HELLO v3, and the session key;
- chat over lab TCP;
- `identity.bin` sealed with `machine.key`;
- the `map.bin` journal and 16 KiB pieces: Linux opens a Rust journal, Rust opens a file stored by Linux;
- one copy on another node, and a check that the ciphertext is still there;
- the grace period and the local penalty;
- the `onion` profile: it runs a real `tor` binary, takes the address only from that process's `hostname`, and dials through SOCKS5. It does not invent an onion address. No `tor` binary means the start fails;
- an `nexxus-smp-v1` queue: the relay stores ciphertext and returns it only to the fingerprint that opened it;
- an `nexxus-xftp-v1` description with no node addresses;
- `--miner`: the node's own files are not placed into the free copies;
- the `drive` folder, a plaintext copy of the vault, not a hidden volume.

The lab profile listens on `0.0.0.0` and publishes this machine's address, so two computers on one network can meet. Control commands are accepted only from the same machine, on `127.0.0.1`.

The plan for these parts, and for what is still open: [docs/PLAN.md](docs/PLAN.md).

## What this build does not contain

Not promised and not included:

- payment, and a check of 16 GiB free;
- a live run of two real onion addresses through the Tor network inside the ordinary test suite;
- a web panel;
- Android, and an Apple client.

Until those exist, this repository is a node for trials, not an app store and not an exchange.

## Two machines

Details: [packaging/TEST-LAB.md](packaging/TEST-LAB.md).

Ubuntu, archive with a binary: [release 0.2.0-lab](https://github.com/PerfectFriend/NeXXuS-Node-Grok-Rust/releases/tag/v0.2.0-lab).

```bash
mkdir -p ~/NeXXuS-Grok-Rust
tar -xzf nexxus-ubuntu-x86_64.tar.gz -C ~/NeXXuS-Grok-Rust
cd ~/NeXXuS-Grok-Rust
sudo ./install.sh
./scripts/start-lab.sh
```

On the second machine, once both nodes are listening on port 4377:

```bash
./scripts/test-peer.sh 'nexxus:1:fingerprint:key@address:4377'
```

`peers` must not be a dash. The file you sent should in time show `copies=1`. Run the same command on the second machine with the first machine's contact.

The Windows archive of that release contains scripts and source. `install.ps1` builds `nexxus.exe` if Rust is installed. There is no prebuilt exe in the archive.

The twelve-word phrase is not written into the logs. Do not put it in a report either.

## Build from source

```bash
cargo test
cargo run -p nexxus -- start --data ~/.nexxus-rs --listen 0.0.0.0 --port 4377
```

Pair tests against the Linux 0.10.0 node:

```bash
NEXXUS_JS_DIR=/path/to/linux-node cargo test --test js_pair --test journal --test replica --test identity
```

While a node is running:

```bash
nexxus ctl --data ~/.nexxus-rs status
nexxus ctl --data ~/.nexxus-rs dial 'nexxus:1:…'
nexxus ctl --data ~/.nexxus-rs put ./file
nexxus ctl --data ~/.nexxus-rs chat FINGERPRINT text
```

The vectors the cryptography is checked against: [vectors/nxx-vectors.json](vectors/nxx-vectors.json). The phrase `legal winner…` in that file is a public BIP39 test, not anyone's vault.

## What the node will not do, even as a goal

It does not repair someone else's silence by itself, and it does not declare a person guilty for the whole network. It does not keep plaintext in the vault. The `drive` folder, when it arrives, stays a plaintext folder beside the ciphertext. It does not make downloads fast. Speed is deliberately not the goal. The goal is that a file cannot be quietly replaced, and cannot be taken away by switching off one server.
