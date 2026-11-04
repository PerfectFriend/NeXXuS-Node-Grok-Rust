# NeXXuS-Node-Grok-Rust

Нода NeXXXUs на Rust. С Linux 0.10.0 уже сходятся ключи, HELLO v3, лабораторный чат и журнал `map.bin`: чанки по 16 КБ и локальное чтение файла. Реплик, льготы и Tor в Rust ещё нет. `nexxus start` по-прежнему только чат и не пишет сейф на диск.

Эталон — [NeXXXUs-Grok](https://github.com/PerfectFriend/NeXXXUs-Grok). Этот репозиторий его не заменяет.

План: [docs/MIGRATION.md](docs/MIGRATION.md). Векторы: [vectors/nxx-vectors.json](vectors/nxx-vectors.json).

```bash
cargo test
NEXXUS_JS_DIR=/путь/к/linux-node cargo test --test js_pair
cargo run -p nexxus -- start --port 4377
```

`nexxus start` слушает только `127.0.0.1`, печатает двенадцать слов один раз и не пишет их на диск. Каталога сейфа нет.
