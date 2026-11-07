# NeXXuS

[English](README.en.md) · **Español** · [Русский](README.md)

![NeXXuS: salir de la ciudad gris hacia una red viva](docs/banner.jpg)

NeXXuS es la base de otro internet. No uno más rápido, ni más cómodo el primer día. Otro en su naturaleza: sin un dueño en el medio, sin un centro de datos obligatorio y sin un disco que se pueda apagar con una sola decisión.

El internet de siempre se queda donde es cómodo usarlo. Aquí se viene cuando un secreto no debe vivir dentro de una sola empresa, y cuando un teléfono viejo enchufado al cargador es un nodo y no basura.

Este repositorio es el nodo en Rust. La referencia del protocolo sigue siendo [NeXXXUs-Grok](https://github.com/PerfectFriend/NeXXXUs-Grok), Linux 0.10.0. Rust no lo sustituye hasta pasar las mismas pruebas. El plan del traslado está en [docs/MIGRATION.md](docs/MIGRATION.md).

## Para qué sirve

Una nube normal guarda el archivo entero en casa de quien cobra. Ve los metadatos, puede negar el acceso y el archivo desaparece con ella si así lo decide.

NeXXuS parte el archivo en trozos de 16 KiB. Cada trozo se cifra aparte. La red no guarda un archivo como archivo. Guarda cifrados mudos. Solo quien tiene el mapa puede reunirlos. El mapa vive en el diario del dueño, no en un escaparate común.

Un nodo no es un servidor en un armario. Es un teléfono viejo, un ordenador de casa o una máquina pequeña, limpia, dejada en la red y enchufada. La persona cede espacio en el disco. A cambio, la red le deja una parte propia, sin tener que alquilarla a un hosting ajeno.

## Cómo está hecho el nodo

1. Doce palabras BIP39. De ellas salen las claves de enlace, la clave de firma y la clave de la caja. La frase se muestra una sola vez.
2. Varios aparatos pueden vivir con la misma clave. Para el diario son una sola casa, no una multitud de extraños.
3. El espacio para la red se toma en tramos de 16 GiB, y solo si hay al menos eso libre. Con menos, el nodo no se vuelve almacén.
4. Al dueño le queda un octavo de lo que entregó. Esa es su caja: secretos y lo que aceptó guardar. El resto lo sostiene la red, no él en persona.
5. Un trozo no se queda en tres copias sobre el mismo estante. Las copias se van a nodos distintos. Cada copia tiene su nonce, así que los cifrados no coinciden byte a byte. No se puede colar una copia en el lugar de otra.
6. En el nodo del dueño queda su propia copia cifrada. La red guarda tres más. Que caiga un disco ajeno no borra el archivo.
7. Si un nodo calla, durante 24 horas no se retira nada. Da tiempo a cargar el teléfono, cambiar de red o levantar la misma clave en otra máquina. Más de un día de silencio, y las copias pasan a nodos que sí responden. Treinta días sin fallo suben la reputación local.
8. La reputación y la multa las recuerda quien pilló el fallo o la sustitución. No hay una lista negra global. Eso sería un centro nuevo.
9. Un trozo cambiado se ve sin abrir el archivo. El identificador es el hash del cifrado. A la pregunta «demuestra que el trozo sigue siendo el mismo» solo se puede responder si en el disco están exactamente esos bytes.
10. Se puede añadir un disco externo al nodo. Más espacio entregado, mayor la parte propia.
11. El espacio por encima de esa parte no se pide «a la nube». Se pide a nodos que guardan trozos de otros. El pago no se comprueba en esta versión y todavía no forma parte del protocolo.
12. Apple es solo cliente. No hay nodo de almacenamiento en iOS: el sistema no entrega el teléfono a un guardado eterno en segundo plano.

## Lo que este nodo ya hace

Compilación **0.2.0-lab**. Coincide con Linux 0.10.0 en:

- las doce palabras, la huella `nxx1`, HELLO v3 y la clave de sesión;
- el chat por TCP de laboratorio;
- `identity.bin`, cerrado con `machine.key`;
- el diario `map.bin` y los trozos de 16 KiB: Linux abre un diario de Rust, Rust abre un archivo guardado por Linux;
- una copia en otro nodo y la prueba de que el cifrado sigue ahí;
- el plazo de gracia y la multa local;
- el perfil `onion`: arranca un binario `tor` de verdad, toma la dirección solo del `hostname` que ese proceso escribió y llama a través de SOCKS5. No se inventa una dirección onion. Si no hay binario `tor`, el arranque falla.

El perfil de laboratorio escucha en `0.0.0.0` y publica la dirección de la máquina, para que dos ordenadores de la misma red puedan encontrarse. Las órdenes de control solo se aceptan desde la propia máquina, en `127.0.0.1`.

## Lo que esta compilación no trae

No está prometido y no está incluido:

- una cola SMP y una descripción de archivo XFTP;
- la carpeta `drive` y un panel web;
- el anuncio de un minero y cualquier pago;
- una prueba en vivo de dos onion reales a través de la red Tor dentro de los tests ordinarios;
- Android y un cliente para Apple.

Hasta que eso exista, este repositorio es un nodo de ensayo, no una tienda de aplicaciones ni una bolsa.

## Dos máquinas

El detalle está en [packaging/TEST-LAB.md](packaging/TEST-LAB.md).

Ubuntu, archivo con binario: [publicación 0.2.0-lab](https://github.com/PerfectFriend/NeXXuS-Node-Grok-Rust/releases/tag/v0.2.0-lab).

```bash
mkdir -p ~/NeXXuS-Grok-Rust
tar -xzf nexxus-ubuntu-x86_64.tar.gz -C ~/NeXXuS-Grok-Rust
cd ~/NeXXuS-Grok-Rust
sudo ./install.sh
./scripts/start-lab.sh
```

En la segunda máquina, cuando los dos nodos ya escuchan el puerto 4377:

```bash
./scripts/test-peer.sh 'nexxus:1:huella:clave@direccion:4377'
```

`peers` no debe ser un guion. El archivo enviado debe llegar con el tiempo a `copies=1`. Repite el comando en la segunda máquina con el contacto de la primera.

El archivo de Windows de esa publicación lleva scripts y el código fuente. `install.ps1` construye `nexxus.exe` si Rust está instalado. No hay un exe ya compilado dentro del archivo.

La frase de doce palabras no se escribe en los registros. Tampoco la pongas en un informe.

## Compilar desde el código

```bash
cargo test
cargo run -p nexxus -- start --data ~/.nexxus-rs --listen 0.0.0.0 --port 4377
```

Pruebas emparejadas con el nodo Linux 0.10.0:

```bash
NEXXUS_JS_DIR=/ruta/al/linux-node cargo test --test js_pair --test journal --test replica --test identity
```

Con el nodo en marcha:

```bash
nexxus ctl --data ~/.nexxus-rs status
nexxus ctl --data ~/.nexxus-rs dial 'nexxus:1:…'
nexxus ctl --data ~/.nexxus-rs put ./archivo
nexxus ctl --data ~/.nexxus-rs chat HUELLA texto
```

Los vectores con los que se contrasta la criptografía: [vectors/nxx-vectors.json](vectors/nxx-vectors.json). La frase `legal winner…` de ese archivo es una prueba pública de BIP39, no la caja de nadie.

## Lo que el nodo no hará ni como meta

No arregla solo el silencio de un nodo ajeno, ni declara a una persona culpable para toda la red. No guarda texto claro en la caja. La carpeta `drive`, cuando llegue, seguirá siendo una carpeta abierta al lado del cifrado. No acelera las descargas. La velocidad, a propósito, no es la meta. La meta es que un archivo no se pueda sustituir en silencio y no se pueda quitar apagando un solo servidor.
