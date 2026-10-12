//! Linux `systemd` user service for the daemon.

use std::path::PathBuf;

use anyhow::{Context, Result};

const UNIT_NAME: &str = "raemoted";

fn unit_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
        .join(format!("{UNIT_NAME}.service")))
}

fn raemoted_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to find current exe")?;
    let dir = exe.parent().context("failed to get exe parent")?;
    Ok(dir.join("raemoted"))
}

/// Whether the systemd user unit is installed.
pub fn is_installed() -> bool {
    unit_path().map(|p| p.exists()).unwrap_or(false)
}

fn unit_content() -> Result<String> {
    let raemoted = raemoted_path()?.display().to_string();
    let config_path = crate::config::config_path(None)?.display().to_string();
    Ok(format!(
        r#"[Unit]
Description=raemote server daemon
After=network.target

[Service]
Type=simple
ExecStart={raemoted} --config {config_path}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"#
    ))
}

/// Write the user unit, reload systemd, and enable and start it.
pub fn install() -> Result<()> {
    let path = unit_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = unit_content()?;
    std::fs::write(&path, &content)
        .with_context(|| format!("failed to write {}", path.display()))?;

    // Reload and enable. Both must succeed: a half-installed user unit that
    // systemd never started is exactly the silent-dead-daemon state an update
    // must not be able to leave behind.
    let output = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output()
        .context("failed to run systemctl daemon-reload")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("systemctl --user daemon-reload failed: {stderr}");
    }

    let output = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", UNIT_NAME])
        .output()
        .context("failed to run systemctl enable")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "systemctl --user enable --now {UNIT_NAME} failed: {stderr}\n\
             a user manager is required — check 'loginctl enable-linger $USER', \
             then run 'raemote service install' again"
        );
    }

    println!("service installed: {}", path.display());
    Ok(())
}

/// Stop and disable the unit, then remove it.
pub fn uninstall() -> Result<()> {
    let path = unit_path()?;
    if !path.exists() {
        eprintln!("service not installed");
        return Ok(());
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", UNIT_NAME])
        .output();

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", UNIT_NAME])
        .output();

    std::fs::remove_file(&path)?;

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .output();

    println!("service uninstalled");
    Ok(())
}

/// Print the unit's status.
pub fn status() -> Result<()> {
    let path = unit_path()?;
    if !path.exists() {
        println!("service not installed");
        return Ok(());
    }
    println!("service unit: {}", path.display());

    let output = std::process::Command::new("systemctl")
        .args(["--user", "status", UNIT_NAME])
        .output()
        .context("failed to run systemctl status")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // systemctl status exits non-zero when the service is not running
    if output.status.success() {
        // Print key lines
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("Active:") || line.starts_with("Main PID:") {
                println!("{line}");
            }
        }
    } else {
        println!("service not running");
        if !stderr.is_empty() {
            // Only show if it's not the common "not found" message
            if !stderr.contains("could not be found") {
                eprintln!("{stderr}");
            }
        }
    }

    Ok(())
}
