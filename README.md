# NeXXuS-Node-Grok-Rust

Нода NeXXXUs на Rust. Уже совпадает с Linux 0.10.0 в ключе, HELLO v3 и лабораторном чате по TCP. Сейфа, копий и Tor ещё нет.

Эталон — [NeXXXUs-Grok](https://github.com/PerfectFriend/NeXXXUs-Grok). Этот репозиторий его не заменяет.

План: [docs/MIGRATION.md](docs/MIGRATION.md). Векторы: [vectors/nxx-vectors.json](vectors/nxx-vectors.json).

```bash
cargo test
NEXXUS_JS_DIR=/путь/к/linux-node cargo test --test js_pair
cargo run -p nexxus -- start --port 4377
```

`nexxus start` слушает только `127.0.0.1`, печатает двенадцать слов один раз и не пишет их на диск. Каталога сейфа нет.
