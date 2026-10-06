//! Raemote — private access to the web apps running on your own machine.
//!
//! Raemote pairs a phone with a computer once, finds the web apps already
//! listening on that computer, and proxies them to the phone over an
//! end-to-end encrypted [iroh] connection. There is no account, no public
//! exposure, and no port forwarding.
//!
//! This crate backs two binaries and exposes the modules they share:
//!
//! - `raemoted` — the daemon: persistent identity, pairing, local web-app
//!   discovery, the HTTP proxy, and local IPC.
//! - `raemote` — the CLI: pairs devices, manages the catalog, installs the
//!   background service, and shows logs.
//!
//! # How it fits together
//!
//! [`identity`] loads the persistent iroh key. [`auth`] mints short-lived
//! pairing tokens and remembers authorized devices. [`bind`] and [`http`] are
//! the two iroh ALPNs: pairing, and the HTTP API guarded by [`auth`]. The
//! [`discovery`] engine and [`catalog`] turn the machine's listening sockets
//! into a list of web apps. [`daemon`] wires it all together, and [`ipc`] lets
//! the CLI drive a running daemon over a Unix socket. [`config`] describes the
//! on-disk configuration, and [`proxy`] and [`lock`] add an outbound proxy and
//! a single-instance guard. [`connector`] is the CLI's own local web client
//! (`raemote connect`), pairing this machine and reverse-proxying a remote
//! server's apps to `127.0.0.1`.
//!
//! # Configuration
//!
//! Configuration is read from `~/.raemote/config.toml` and may be overridden by
//! `RAEMOTE_*` environment variables. See [`config`] for the schema.
//!
//! # Getting started
//!
//! The [README](https://github.com/raemote/raemote_server#readme) covers
//! installation, pairing, and everyday use.
//!
//! [iroh]: https://iroh.computer

#![warn(missing_docs)]

pub mod auth;
pub mod bind;
pub mod catalog;
pub mod config;
pub mod connector;
pub mod daemon;
pub mod discovery;
pub mod http;
pub mod identity;
pub mod iroh_stream;
pub mod ipc;
pub mod lock;
pub mod logs;
pub mod proxy;
pub mod qr;
pub mod service;
