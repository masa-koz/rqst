use libc::{
    in6_pktinfo, in_pktinfo, iovec, msghdr, recvmsg, sendmsg, setsockopt, sockaddr_in,
    sockaddr_in6, sockaddr_storage, AF_INET, AF_INET6, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN,
    CMSG_NXTHDR, CMSG_SPACE, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO, IPV6_RECVPKTINFO, IP_PKTINFO,
};
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::ptr;
use tokio::net::{lookup_host, ToSocketAddrs, UdpSocket};

pub async fn bind_sas<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr).await?;
    let local_addr = sock.local_addr()?;

    let (level, optname) = if local_addr.is_ipv4() {
        (IPPROTO_IP as i32, IP_PKTINFO as i32)
    } else {
        (IPPROTO_IPV6 as i32, IPV6_RECVPKTINFO as i32)
    };
    let optval = [1u32; 1];
    let res = unsafe {
        setsockopt(
            sock.as_raw_fd() as _,
            level as _,
            optname as _,
            optval.as_ptr() as _,
            mem::size_of_val(&optval) as _,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(sock)
}

pub async fn recv_sas(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, Option<SocketAddr>, Option<SocketAddr>)> {
    let mut control = [0u8; 128];
    let mut source: sockaddr_storage = unsafe { mem::zeroed() };

    let mut msg = msghdr {
        msg_name: &mut source as *mut _ as *mut _,
        msg_namelen: mem::size_of_val(&source) as _,
        msg_iov: &mut iovec {
            iov_base: buf.as_mut_ptr() as _,
            iov_len: buf.len() as _,
        },
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut _,
        msg_controllen: mem::size_of_val(&control) as _,
        msg_flags: 0,
    };

    socket.try_io(tokio::io::Interest::READABLE, || {
        let nb = { unsafe { recvmsg(socket.as_raw_fd(), &mut msg, 0) } };
        if nb >= 0 {
            let mut destination_address = None;
            unsafe {
                let mut cmsg = CMSG_FIRSTHDR(&msg);
                while cmsg != ptr::null_mut() {
                    if (*cmsg).cmsg_level == IPPROTO_IP as i32
                        && (*cmsg).cmsg_type == IP_PKTINFO as i32
                        && (*cmsg).cmsg_len
                            >= CMSG_LEN(mem::size_of::<in_pktinfo>() as u32) as usize
                    {
                        let info: in_pktinfo = ptr::read(CMSG_DATA(cmsg) as *const _);
                        let destination = sockaddr_in {
                            sin_family: AF_INET as _,
                            sin_addr: info.ipi_addr,
                            sin_port: 0,
                            sin_zero: [0u8; 8],
                        };
                        let (_, address) = socket2::SockAddr::init(|addr_storage, len| {
                            *len = mem::size_of_val(&destination) as _;
                            std::ptr::copy_nonoverlapping(&destination, addr_storage as _, 1);
                            Ok(())
                        })?;
                        destination_address = address.as_socket()
                    }
                    if (*cmsg).cmsg_level == IPPROTO_IPV6 as i32
                        && (*cmsg).cmsg_type == IPV6_PKTINFO as i32
                        && (*cmsg).cmsg_len
                            >= CMSG_LEN(mem::size_of::<in6_pktinfo>() as u32) as usize
                    {
                        let info: in6_pktinfo = ptr::read(CMSG_DATA(cmsg) as *const _);
                        let mut destination: sockaddr_in6 = mem::zeroed();
                        destination.sin6_family = AF_INET6 as _;
                        destination.sin6_addr = info.ipi6_addr;
                        let (_, address) = socket2::SockAddr::init(|addr_storage, len| {
                            *len = mem::size_of_val(&destination) as _;
                            std::ptr::copy_nonoverlapping(&destination, addr_storage as _, 1);
                            Ok(())
                        })?;
                        destination_address = address.as_socket()
                    }
                    cmsg = CMSG_NXTHDR(&msg, cmsg);
                }
            }
            let source_address = unsafe {
                let (_, address) = socket2::SockAddr::init(|addr_storage, len| {
                    *len = mem::size_of_val(&source) as _;
                    ptr::copy_nonoverlapping(&source, addr_storage as _, 1);
                    Ok(())
                })?;
                address.as_socket()
            };
            Ok((nb as usize, source_address, destination_address))
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
}

pub async fn send_sas<R: ToSocketAddrs, L: ToSocketAddrs>(
    socket: &UdpSocket,
    buf: &[u8],
    remote: R,
    local: L,
) -> io::Result<usize> {
    let mut addrs = lookup_host(remote).await?;
    let remote = match addrs.next() {
        Some(remote) => socket2::SockAddr::from(remote),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no addresses to send data to",
            ));
        }
    };

    let mut addrs = lookup_host(local).await?;
    let local = match addrs.next() {
        Some(local) => socket2::SockAddr::from(local),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no addresses to send data from",
            ));
        }
    };

    let mut control = [0u8; 128];

    let mut msg = msghdr {
        msg_name: remote.as_ptr() as *mut _,
        msg_namelen: remote.len(),
        msg_iov: &mut iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len() as _,
        },
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr() as *mut _,
        msg_controllen: 0,
        msg_flags: 0,
    };

    match local.family() as i32 {
        AF_INET => {
            let local: sockaddr_in = unsafe { ptr::read(local.as_ptr() as _) };
            let mut info: in_pktinfo = unsafe { mem::zeroed() };
            info.ipi_spec_dst = local.sin_addr;

            msg.msg_controllen +=
                unsafe { CMSG_SPACE(mem::size_of::<in_pktinfo>() as u32) as usize };
            unsafe {
                let mut cmsg = CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = IPPROTO_IP as _;
                (*cmsg).cmsg_type = IP_PKTINFO as _;
                (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<in_pktinfo>() as u32) as usize;
                ptr::copy(&info, CMSG_DATA(cmsg) as *mut _, 1);
            }
        }
        AF_INET6 => {
            let local: sockaddr_in6 = unsafe { ptr::read(local.as_ptr() as _) };
            let mut info: in6_pktinfo = unsafe { mem::zeroed() };
            info.ipi6_addr = local.sin6_addr;

            msg.msg_controllen +=
                unsafe { CMSG_SPACE(mem::size_of::<in6_pktinfo>() as u32) as usize };
            unsafe {
                let mut cmsg = CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = IPPROTO_IPV6 as _;
                (*cmsg).cmsg_type = IPV6_PKTINFO as _;
                (*cmsg).cmsg_len = CMSG_LEN(mem::size_of::<in6_pktinfo>() as u32) as usize;
                ptr::copy(&info, CMSG_DATA(cmsg) as *mut _, 1);
            }
        }
        _ => {
            return Err(io::Error::new(io::ErrorKind::Other, "not an inet addr"));
        }
    };

    socket.try_io(tokio::io::Interest::WRITABLE, || {
        let nb = unsafe { sendmsg(socket.as_raw_fd(), &mut msg, 0) };

        if nb >= 0 {
            Ok(nb as usize)
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_recv_sas_ipv4() {
        use if_addrs::{get_if_addrs, IfAddr};
        use std::net::IpAddr;

        let receiver = bind_sas("0.0.0.0:0").await.unwrap();
        let recv_port = receiver.local_addr().unwrap().port();
        let sender = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let send_port = sender.local_addr().unwrap().port();
        let send_buf = b"hello";
        let mut recv_buf = vec![0u8; 1500];

        for iface in get_if_addrs().unwrap() {
            match iface.addr {
                IfAddr::V4(addr) => {
                    println!("{:?}", addr.ip);
                    let remote = SocketAddr::new(IpAddr::V4(addr.ip), recv_port);
                    let _ = sender.writable().await;
                    sender.send_to(send_buf, remote).await.unwrap();
                    let _ = sender.writable().await;
                    sender.send_to(send_buf, remote).await.unwrap();

                    let _ = receiver.readable().await;
                    if let Ok((n, from, to)) = recv_sas(&receiver, &mut recv_buf).await {
                        assert_eq!(n, 5);
                        assert_eq!(from, Some(SocketAddr::new(IpAddr::V4(addr.ip), send_port)));
                        assert_eq!(to, Some(SocketAddr::new(IpAddr::V4(addr.ip), 0)));
                    }

                    if let Ok((n, from, to)) = recv_sas(&receiver, &mut recv_buf).await {
                        assert_eq!(n, 5);
                        assert_eq!(from, Some(SocketAddr::new(IpAddr::V4(addr.ip), send_port)));
                        assert_eq!(to, Some(SocketAddr::new(IpAddr::V4(addr.ip), 0)));
                    }
                }
                IfAddr::V6(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn test_recv_sas_ipv6() {
        use if_addrs::{get_if_addrs, IfAddr};
        use std::net::IpAddr;

        let receiver = bind_sas("[::]:0").await.unwrap();
        let recv_port = receiver.local_addr().unwrap().port();
        let sender = UdpSocket::bind("[::]:0").await.unwrap();
        let send_port = sender.local_addr().unwrap().port();
        let send_buf = b"hello";
        let mut recv_buf = vec![0u8; 1500];

        for iface in get_if_addrs().unwrap() {
            match iface.addr {
                IfAddr::V6(addr) => {
                    let remote = SocketAddr::new(IpAddr::V6(addr.ip), recv_port);
                    let _ = sender.writable().await;
                    sender.send_to(send_buf, remote).await.unwrap();
                    let _ = sender.writable().await;
                    sender.send_to(send_buf, remote).await.unwrap();

                    let _ = receiver.readable().await;
                    if let Ok((n, from, to)) = recv_sas(&receiver, &mut recv_buf).await {
                        assert_eq!(n, 5);
                        assert_eq!(from, Some(SocketAddr::new(IpAddr::V6(addr.ip), send_port)));
                        assert_eq!(to, Some(SocketAddr::new(IpAddr::V6(addr.ip), 0)));
                    }

                    if let Ok((n, from, to)) = recv_sas(&receiver, &mut recv_buf).await {
                        assert_eq!(n, 5);
                        assert_eq!(from, Some(SocketAddr::new(IpAddr::V6(addr.ip), send_port)));
                        assert_eq!(to, Some(SocketAddr::new(IpAddr::V6(addr.ip), 0)));
                    }
                }
                IfAddr::V4(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn test_send_sas_ipv4() {
        use if_addrs::{get_if_addrs, IfAddr};
        use std::net::{IpAddr, Ipv4Addr};

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_port = receiver.local_addr().unwrap().port();
        let sender = bind_sas("0.0.0.0:0").await.unwrap();
        let send_port = sender.local_addr().unwrap().port();
        let send_buf = b"hello";
        let mut recv_buf = vec![0u8; 1500];

        for iface in get_if_addrs().unwrap() {
            match iface.addr {
                IfAddr::V4(addr) => {
                    println!("{:?}", addr.ip);
                    let local = SocketAddr::new(IpAddr::V4(addr.ip), 0);
                    let _ = sender.writable().await;
                    let len = send_sas(
                        &sender,
                        send_buf,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), recv_port),
                        local,
                    )
                    .await
                    .unwrap();
                    assert_eq!(len, 5);
                    let _ = receiver.readable().await;
                    let (len, from) = receiver.recv_from(&mut recv_buf).await.unwrap();
                    assert_eq!(len, 5);
                    assert_eq!(from, SocketAddr::new(IpAddr::V4(addr.ip), send_port));
                }
                IfAddr::V6(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn test_send_sas_ipv6() {
        use if_addrs::{get_if_addrs, IfAddr};
        use std::net::{IpAddr, Ipv6Addr};

        let receiver = UdpSocket::bind("[::1]:0").await.unwrap();
        let recv_port = receiver.local_addr().unwrap().port();
        let sender = bind_sas("[::]:0").await.unwrap();
        let send_port = sender.local_addr().unwrap().port();
        let send_buf = b"hello";
        let mut recv_buf = vec![0u8; 1500];

        for iface in get_if_addrs().unwrap() {
            match iface.addr {
                IfAddr::V6(addr) => {
                    println!("{:?}", addr.ip);
                    let local = SocketAddr::new(IpAddr::V6(addr.ip), 0);
                    let _ = sender.writable().await;
                    let len = send_sas(
                        &sender,
                        send_buf,
                        SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                            recv_port,
                        ),
                        local,
                    )
                    .await
                    .unwrap();
                    assert_eq!(len, 5);
                    let _ = receiver.readable().await;
                    let (len, from) = receiver.recv_from(&mut recv_buf).await.unwrap();
                    assert_eq!(len, 5);
                    assert_eq!(from, SocketAddr::new(IpAddr::V6(addr.ip), send_port));
                }
                IfAddr::V4(_) => {}
            }
        }
    }
}
