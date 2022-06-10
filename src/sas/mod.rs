#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
pub use self::unix::*;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use self::windows::*;

use std::io;
use std::net::SocketAddr;
use tokio::net::{lookup_host, UdpSocket, ToSocketAddrs};

pub async fn recv_sas(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, Option<SocketAddr>, Option<SocketAddr>)> {
    loop {
        let _ = socket.readable().await;
        match try_recv_sas(socket, buf) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            x => return x,
        }
    }
}

pub async fn send_sas<R: ToSocketAddrs, L: ToSocketAddrs>(
    socket: &UdpSocket,
    buf: &[u8],
    remote: R,
    local: L,
) -> io::Result<usize> {
    let mut addrs = lookup_host(remote).await?;
    let remote = match addrs.next() {
        Some(remote) => remote,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no addresses to send data to",
            ));
        }
    };

    let mut addrs = lookup_host(local).await?;
    let local = match addrs.next() {
        Some(local) => local,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no addresses to send data from",
            ));
        }
    };

    loop {
        let _ = socket.writable().await;
        match try_send_sas(socket, buf, remote, local) {
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            x => return x,
        }
    }
}
