use std::{fs, process::Command};

fn provider(config: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_swap-provider"));
    command.env_clear().arg("--config").arg(config);
    command
}

/// #107: `--no-homeserver` turns the mode off for one run, the config file turns it off for
/// every run, the environment sits between them, and an unpassed flag leaves the lower layers
/// alone.
#[test]
fn the_flag_the_environment_and_the_config_file_all_set_the_homeserver_mode() {
    let dir = std::env::temp_dir().join(format!("no-homeserver-cli-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.toml");
    fs::write(&config, "").unwrap();
    let show = |command: &mut Command| {
        let output = command.arg("--show-config").output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    };

    assert!(show(&mut provider(&config)).contains("homeserver = true"));
    assert!(show(provider(&config).arg("--no-homeserver")).contains("homeserver = false"));

    fs::write(&config, "homeserver = false\n").unwrap();
    assert!(show(&mut provider(&config)).contains("homeserver = false"));
    assert!(
        show(provider(&config).env("PUBKY_SWAP_HOMESERVER", "true")).contains("homeserver = true")
    );
    fs::remove_dir_all(dir).unwrap();
}

/// The daemon refuses a setting that needs the homeserver before it reads its identity, so the
/// operator sees the conflict rather than a sign-in error.
#[test]
fn a_homeserver_free_provider_refuses_the_offer_broadcast_at_startup() {
    let dir = std::env::temp_dir().join(format!("no-homeserver-run-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.toml");
    fs::write(&config, "").unwrap();
    let output = provider(&config)
        .arg("--no-homeserver")
        .arg("--broadcast-offer")
        .arg("--data-dir")
        .arg(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("broadcast_offer"), "{stderr}");
    assert!(stderr.contains("--no-homeserver"), "{stderr}");
    fs::remove_dir_all(dir).unwrap();
}
