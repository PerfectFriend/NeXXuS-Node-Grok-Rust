# NeXXuS-Node-Grok-Rust

Нода NeXXXUs на Rust. С Linux 0.10.0 сходятся ключи, HELLO v3, лабораторный чат, `identity.bin`, журнал `map.bin`, копия, проверка чанка и профиль `onion`: бинарник `tor`, адрес только из `hostname`, звонок через SOCKS5. Свой onion не выдумывается. Живой прогон через сеть Tor в обычный тест не входит.

Эталон — [NeXXXUs-Grok](https://github.com/PerfectFriend/NeXXXUs-Grok). Этот репозиторий его не заменяет.

План: [docs/MIGRATION.md](docs/MIGRATION.md). Векторы: [vectors/nxx-vectors.json](vectors/nxx-vectors.json).

```bash
cargo test
NEXXUS_JS_DIR=/путь/к/linux-node cargo test --test js_pair --test journal --test replica --test identity
cargo run -p nexxus -- start --data ~/.nexxus-rs --port 4377
```

Пакет для проверки двух компьютеров в одной сети: [packaging/TEST-LAB.md](packaging/TEST-LAB.md). В нём лабораторный чат, сейф и одна копия. Очереди SMP и описания XFTP в пакет 0.2.0-lab не входят.
