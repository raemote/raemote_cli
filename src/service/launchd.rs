//! macOS `launchd` user agent for the daemon.

use std::path::PathBuf;

use anyhow::{Context, Result};

const PLIST_LABEL: &str = "com.raemote.raemoted";

/// The real user id. launchd's `gui/<uid>` domain needs the uid, not the pid.
fn uid() -> u32 {
    // SAFETY: `getuid` is always safe and cannot fail.
    unsafe { libc::getuid() }
}

fn plist_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{PLIST_LABEL}.plist")))
}

fn raemoted_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to find current exe")?;
    let dir = exe.parent().context("failed to get exe parent")?;
    Ok(dir.join("raemoted"))
}

/// Whether the LaunchAgent plist is installed.
pub fn is_installed() -> bool {
    plist_path().map(|p| p.exists()).unwrap_or(false)
}

fn plist_content() -> Result<String> {
    let raemoted = raemoted_path()?;
    let config_path = crate::config::config_path(None)?;
    // Records are already persisted (rotated, count-capped) by the daemon's
    // own `~/.raemote` appender (daemon.rs `init_tracing`), so stderr goes to
    // /dev/null: nothing from the daemon lands in world-writable, unmanaged
    // sinks like /tmp.
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--config</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>
"#,
        raemoted.display(),
        config_path.display()
    ))
}

/// Write the LaunchAgent plist and load it.
pub fn install() -> Result<()> {
    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = plist_content()?;
    std::fs::write(&path, &content)
        .with_context(|| format!("failed to write {}", path.display()))?;
    crate::identity::restrict(&path, 0o600);

    // Bootstrap the service
    let target = format!("gui/{}", uid());
    let plist_str = path.to_str().context("plist path is not valid UTF-8")?;
    let output = std::process::Command::new("launchctl")
        .args(["bootstrap", &target, plist_str])
        .output()
        .context("failed to run launchctl bootstrap")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "Already loaded" is not an error
        if !stderr.contains("Already loaded") {
            eprintln!("launchctl bootstrap: {stderr}");
        }
    }

    println!("service installed: {}", path.display());
    Ok(())
}

/// Unload the LaunchAgent and remove its plist.
pub fn uninstall() -> Result<()> {
    let path = plist_path()?;
    if !path.exists() {
        eprintln!("service not installed");
        return Ok(());
    }

    let target = format!("gui/{}", uid());
    let plist_str = path.to_str().context("plist path is not valid UTF-8")?;
    let output = std::process::Command::new("launchctl")
        .args(["bootout", &target, plist_str])
        .output()
        .context("failed to run launchctl bootout")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Could not find specified service") {
            eprintln!("launchctl bootout: {stderr}");
        }
    }

    std::fs::remove_file(&path)?;
    println!("service uninstalled");
    Ok(())
}

/// Print the LaunchAgent's status.
pub fn status() -> Result<()> {
    let path = plist_path();
    if let Ok(p) = path {
        if p.exists() {
            println!("service plist: {}", p.display());
        } else {
            println!("service not installed");
            return Ok(());
        }
    }

    let target = format!("gui/{}/{}", uid(), PLIST_LABEL);
    let output = std::process::Command::new("launchctl")
        .args(["print", &target])
        .output()
        .context("failed to run launchctl print")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Extract key info
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("pid =") || line.starts_with("state =") || line.starts_with("last exit status =") {
                println!("{line}");
            }
        }
    } else {
        println!("service not running");
    }

    Ok(())
}
