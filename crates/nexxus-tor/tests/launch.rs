use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use nexxus_tor::{render_torrc, start_tor};

#[test]
fn torrc_names_the_service_directory() {
    let text = render_torrc(
        std::path::Path::new("/tmp/nexxus-tor-data"),
        9050,
        std::path::Path::new("/tmp/nexxus-tor-hs"),
        4377,
    );
    assert!(text.contains("HiddenServiceDir \"/tmp/nexxus-tor-hs\""));
    assert!(text.contains("HiddenServicePort 4377 127.0.0.1:4377"));
    assert!(text.contains("SocksPort 127.0.0.1:9050"));
}

#[test]
fn missing_binary_is_an_error() {
    let dir = std::env::temp_dir().join(format!("nxx-tor-miss-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let err = start_tor("/no/such/nexxus-tor", &dir, 18811, Duration::from_secs(2)).unwrap_err();
    assert!(err.contains("Не удалось запустить Tor"), "{err}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn hostname_comes_only_from_the_process() {
    let onion = format!("{}.onion", "d".repeat(56));
    let dir = std::env::temp_dir().join(format!("nxx-tor-stub-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("tor-stub");
    fs::write(
        &stub,
        format!(
            "#!/bin/sh\nrc=\nprev=\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-f\" ]; then rc=\"$arg\"; fi\n  prev=\"$arg\"\ndone\nhs=$(sed -n 's/^HiddenServiceDir \"\\(.*\\)\"$/\\1/p' \"$rc\")\nmkdir -p \"$hs\"\nprintf '%s\\n' '{0}' > \"$hs/hostname\"\nexec sleep 30\n",
            onion
        ),
    )
    .unwrap();
    let mut mode = fs::metadata(&stub).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&stub, mode).unwrap();
    let tor = start_tor(stub.to_str().unwrap(), &dir.join("root"), 18821, Duration::from_secs(5)).unwrap();
    assert_eq!(tor.onion, onion);
    drop(tor);
    let bad = dir.join("bad-stub");
    fs::write(&bad, "#!/bin/sh\nrc=\nprev=\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-f\" ]; then rc=\"$arg\"; fi\n  prev=\"$arg\"\ndone\nhs=$(sed -n 's/^HiddenServiceDir \"\\(.*\\)\"$/\\1/p' \"$rc\")\nmkdir -p \"$hs\"\nprintf 'not-an-onion\\n' > \"$hs/hostname\"\nexec sleep 30\n").unwrap();
    let mut mode = fs::metadata(&bad).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&bad, mode).unwrap();
    let err = start_tor(bad.to_str().unwrap(), &dir.join("bad"), 18822, Duration::from_millis(700)).unwrap_err();
    assert!(err.contains("не подставляется"), "{err}");
    let _ = fs::remove_dir_all(&dir);
}
