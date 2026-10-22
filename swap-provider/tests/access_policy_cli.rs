use std::{fs, process::Command};

#[test]
fn offline_validation_uses_all_configuration_layers_and_names_invalid_entries() {
    let dir = std::env::temp_dir().join(format!("policy-cli-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let policy = dir.join("policy.json");
    let config = dir.join("config.toml");
    fs::write(
        &policy,
        r#"{"mode":"approved_only","allowed":[],"blocked":[]}"#,
    )
    .unwrap();
    fs::write(&config, "").unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_swap-provider"));
        command
            .env_clear()
            .arg("--config")
            .arg(&config)
            .arg("--check-access-policy");
        command
    };
    assert!(!command().output().unwrap().status.success());
    assert!(command()
        .arg("--access-policy-file")
        .arg(&policy)
        .output()
        .unwrap()
        .status
        .success());
    assert!(command()
        .env("PUBKY_SWAP_ACCESS_POLICY_FILE", &policy)
        .output()
        .unwrap()
        .status
        .success());
    fs::write(
        &config,
        format!("access_policy_file = {:?}\n", policy.display().to_string()),
    )
    .unwrap();
    assert!(command().output().unwrap().status.success());
    let valid = pubky_transport::identity_from_secret(&[41; 32]);
    fs::write(
        &policy,
        serde_json::json!({"mode":"open", "allowed":[valid, "n".repeat(52)], "blocked":[]})
            .to_string(),
    )
    .unwrap();
    let output = command().output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("invalid allowed pubky at entry 2"));
    fs::remove_dir_all(dir).unwrap();
}
