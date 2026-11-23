//! A real `rhypedb-server` for integration tests.
//!
//! Tests run against the same server and schema production uses, not a fake.
//! The binary comes from `RHYPEDB_SERVER_BIN`, else `rhypedb-server` on
//! `PATH`; install the pinned version with `scripts/install-rhypedb.sh`. A
//! missing binary fails the test with instructions; it never skips.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A running server in its own temporary data directory.
pub struct RhypeServer {
    child: Option<Child>,
    dir: tempfile::TempDir,
    http_port: u16,
    tcp_port: u16,
}

fn binary() -> PathBuf {
    std::env::var_os("RHYPEDB_SERVER_BIN")
        .map_or_else(|| PathBuf::from("rhypedb-server"), PathBuf::from)
}

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema.rhype")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("no free port")
}

impl RhypeServer {
    /// Start a server with the repository's `schema.rhype`.
    pub fn start() -> Self {
        let mut s = Self {
            child: None,
            dir: tempfile::tempdir().expect("tempdir"),
            http_port: free_port(),
            tcp_port: free_port(),
        };
        s.spawn();
        s
    }

    fn spawn(&mut self) {
        let bin = binary();
        let child = Command::new(&bin)
            .arg("--schema")
            .arg(schema_path())
            .arg("--data-dir")
            .arg(self.dir.path().join("data"))
            .arg("--listen")
            .arg(format!("127.0.0.1:{}", self.http_port))
            .arg("--tcp-listen")
            .arg(self.tcp_addr())
            .arg("--no-sync")
            .stdout(Stdio::null())
            .stderr(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.dir.path().join("server.log"))
                    .map_or_else(|_| Stdio::null(), Stdio::from),
            )
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "cannot start {} ({e}). Install the pinned server with \
                     scripts/install-rhypedb.sh and put it on PATH, or set \
                     RHYPEDB_SERVER_BIN",
                    bin.display()
                )
            });
        self.child = Some(child);
        self.wait_ready();
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect(self.tcp_addr()).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "rhypedb-server did not start listening on {}",
            self.tcp_addr()
        );
    }

    /// The binary-protocol address.
    pub fn tcp_addr(&self) -> String {
        format!("127.0.0.1:{}", self.tcp_port)
    }

    /// Stop the server (data is kept).
    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Start it again on the same ports and data.
    pub fn restart(&mut self) {
        self.stop();
        self.spawn();
    }
}

impl RhypeServer {
    /// The server's stderr so far (for diagnosing a failing test).
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("server.log")).unwrap_or_default()
    }
}

impl Drop for RhypeServer {
    fn drop(&mut self) {
        self.stop();
    }
}
