use bytes::{Bytes, BytesMut};
use if_watch::IfWatcher;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use ring::rand::*;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::sas::try_recv_sas;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

type ConnectionHandle = u64;

struct QuicActor {
    receiver: mpsc::Receiver<ActorMessage>,
    udp: UdpSocket,
    udp_port: u16,
    udp6: UdpSocket,
    udp6_port: u16,
    ifwatcher: IfWatcher,
    config: quiche::Config,
    keylog: Option<File>,
    conn_id_len: usize,
    client_cert_required: bool,
    next_conn_handle: ConnectionHandle,
    conn_ids: QuicConnectionIdMap,
    conns: QuicConnectionMap,
    wait_conn_handles: VecDeque<ConnectionHandle>,
    accept_requests: VecDeque<AcceptRequest>,
    shutdown: bool,
    buf: Vec<u8>,
    out: Vec<u8>,
    _shutdown_complete: mpsc::Sender<()>,
}

#[derive(Debug)]
enum ActorMessage {
    Accept {
        respond_to: oneshot::Sender<Result<ConnectionHandle>>,
    },
    Connect {
        url: url::Url,
        respond_to: oneshot::Sender<Result<ConnectionHandle>>,
    },
    RecvDgramReadness {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<()>>,
    },
    RecvDgram {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<Option<Bytes>>>,
    },
    RecvDgramVectored {
        conn_handle: ConnectionHandle,
        max_len: usize,
        respond_to: oneshot::Sender<Result<Vec<Bytes>>>,
    },
    RecvDgramInfo {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<(Option<usize>, usize, usize)>>,
    },
    SendDgram {
        conn_handle: ConnectionHandle,
        buf: Bytes,
        respond_to: oneshot::Sender<Result<()>>,
    },
    Stats {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<quiche::Stats>>,
    },
    Close {
        conn_handle: ConnectionHandle,
        respond_to: oneshot::Sender<Result<()>>,
    },
}

struct QuicConnection {
    quiche_conn: quiche::Connection,
    conn_handle: ConnectionHandle,
    before_established: bool,
    connect_request: Option<ConnectRequest>,
    recv_dgram_readness_requests: VecDeque<RecvDgramReadnessRequest>,
    send_dgram_requests: VecDeque<SendDgramRequest>,
}
type QuicConnectionIdMap = HashMap<quiche::ConnectionId<'static>, ConnectionHandle>;
type QuicConnectionMap = HashMap<ConnectionHandle, QuicConnection>;

struct AcceptRequest {
    respond_to: oneshot::Sender<Result<ConnectionHandle>>,
}

struct ConnectRequest {
    respond_to: oneshot::Sender<Result<ConnectionHandle>>,
}

struct RecvDgramReadnessRequest {
    respond_to: oneshot::Sender<Result<()>>,
}

struct SendDgramRequest {
    buf: Bytes,
    respond_to: oneshot::Sender<Result<()>>,
}

impl QuicActor {
    async fn new(
        receiver: mpsc::Receiver<ActorMessage>,
        udp: UdpSocket,
        udp6: UdpSocket,
        config: quiche::Config,
        keylog: Option<File>,
        conn_id_len: usize,
        client_cert_required: bool,
        shutdown_complete: mpsc::Sender<()>,
    ) -> Self {
        let ifwatcher = IfWatcher::new().await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let udp6_addr = udp6.local_addr().unwrap();
        QuicActor {
            receiver,
            udp,
            udp6,
            udp_port: udp_addr.port(),
            udp6_port: udp6_addr.port(),
            ifwatcher,
            config,
            keylog,
            conn_id_len,
            client_cert_required,
            next_conn_handle: 0,
            conn_ids: QuicConnectionIdMap::new(),
            conns: QuicConnectionMap::new(),
            wait_conn_handles: VecDeque::new(),
            accept_requests: VecDeque::new(),
            shutdown: false,
            buf: vec![0; 4096],
            out: vec![0; 1350],
            _shutdown_complete: shutdown_complete,
        }
    }

    async fn handle_message(&mut self, msg: ActorMessage) {
        match msg {
            ActorMessage::Accept { respond_to } => {
                if let Some(conn_handle) = self.wait_conn_handles.pop_front() {
                    let _ = respond_to.send(Ok(conn_handle));
                } else {
                    self.accept_requests.push_back(AcceptRequest { respond_to });
                }
            }
            ActorMessage::Connect { url, respond_to } => {
                let to = url.to_socket_addrs().unwrap().next().unwrap();
                let udp = if to.is_ipv4() { &self.udp } else { &self.udp6 };
                let from = udp.local_addr().unwrap();
                // Generate a random source connection ID for the connection.
                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                let scid = &mut scid[0..self.conn_id_len];
                ring::rand::SystemRandom::new().fill(&mut scid[..]).unwrap();

                let scid = quiche::ConnectionId::from_ref(&scid).into_owned();
                // Create a QUIC connection and initiate handshake.
                let mut conn = quiche::connect(
                    url.domain(),
                    &scid.clone(),
                    from,
                    to,
                    &mut self.config,
                )
                .unwrap();

                if let Some(keylog) = &self.keylog {
                    if let Ok(keylog) = keylog.try_clone() {
                        conn.set_keylog(Box::new(keylog));
                    }
                }
                let (write, send_info) = conn.send(&mut self.out).expect("initial send failed");

                let udp = if to.is_ipv4() { &self.udp } else { &self.udp6 };
                let _written = udp
                    .send_to(&self.out[..write], &send_info.to)
                    .await
                    .unwrap();

                let new_conn_handle = self.next_conn_handle;
                self.conns.insert(
                    new_conn_handle,
                    QuicConnection {
                        quiche_conn: conn,
                        conn_handle: new_conn_handle,
                        before_established: true,
                        connect_request: Some(ConnectRequest { respond_to }),
                        recv_dgram_readness_requests: VecDeque::new(),
                        send_dgram_requests: VecDeque::new(),
                    },
                );
                self.conn_ids.insert(scid, new_conn_handle);
                self.next_conn_handle += 1;
            }
            ActorMessage::RecvDgramReadness {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    if conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        let _ = respond_to.send(Ok(()));
                    } else {
                        conn.recv_dgram_readness_requests
                            .push_back(RecvDgramReadnessRequest { respond_to });
                    }
                } else {
                    let _ = respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::RecvDgram {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    if conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        let mut buf = BytesMut::with_capacity(1350);
                        buf.resize(1350, 0);
                        match conn.quiche_conn.dgram_recv(&mut buf) {
                            Ok(len) => {
                                buf.truncate(len);
                                let _ = respond_to.send(Ok(Some(buf.freeze())));
                            }
                            Err(e) if e == quiche::Error::Done => {
                                let _ = respond_to.send(Ok(None));
                            }
                            Err(e) => {
                                let _ = respond_to
                                    .send(Err(format!("dgram_recv failed: {:?}", e).into()));
                            }
                        }
                    } else {
                        let _ = respond_to.send(Ok(None));
                    }
                } else {
                    let _ = respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::RecvDgramVectored {
                conn_handle,
                max_len,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let mut bufs = Vec::new();
                    while conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        if bufs.len() > max_len {
                            break;
                        }
                        let mut buf = BytesMut::with_capacity(1350);
                        buf.resize(1350, 0);
                        match conn.quiche_conn.dgram_recv(&mut buf) {
                            Ok(len) => {
                                buf.truncate(len);
                                bufs.push(buf.freeze());
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                    let _ = respond_to.send(Ok(bufs));
                } else {
                    let _ = respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::RecvDgramInfo {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let front_len = conn.quiche_conn.dgram_recv_front_len();
                    let queue_byte_size = conn.quiche_conn.dgram_recv_queue_byte_size();
                    let queue_len = conn.quiche_conn.dgram_recv_queue_len();

                    let _ = respond_to.send(Ok((front_len, queue_byte_size, queue_len)));
                } else {
                    let _ = respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::SendDgram {
                conn_handle,
                buf,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    match conn.quiche_conn.dgram_send(&buf) {
                        Ok(_) => {
                            let _ = respond_to.send(Ok(()));
                        }
                        Err(e) if e == quiche::Error::Done => {
                            conn.send_dgram_requests
                                .push_back(SendDgramRequest { buf, respond_to });
                        }
                        Err(e) => {
                            let _ =
                                respond_to.send(Err(format!("dgram_send failed: {:?}", e).into()));
                        }
                    }
                } else {
                    let _ = respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::Stats {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    let stats = conn.quiche_conn.stats();
                    let _ = respond_to.send(Ok(stats));
                } else {
                    let _ = respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
            ActorMessage::Close {
                conn_handle,
                respond_to,
            } => {
                if let Some(conn) = self.conns.get_mut(&conn_handle) {
                    conn.quiche_conn.close(true, 0x00, b"").ok();
                    let _ = respond_to.send(Ok(()));
                } else {
                    let _ = respond_to.send(Err(format!("No Connection: {:?}", conn_handle).into()));
                }
            }
        }
    }

    async fn handle_udp_dgram(&mut self, len: usize, from: SocketAddr, to: Option<SocketAddr>) {
        trace!("Recv UDP {} bytes", len);
        let udp = if from.is_ipv4() {
            &self.udp
        } else {
            &self.udp6
        };
        let to = if to.is_some() {
            to.unwrap()
        } else {
            udp.local_addr().unwrap()
        };
        let hdr = match quiche::Header::from_slice(&mut self.buf, quiche::MAX_CONN_ID_LEN) {
            Ok(v) => v,
            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                return;
            }
        };

        let conn_handle = if !self.conn_ids.contains_key(&hdr.dcid) {
            if hdr.ty != quiche::Type::Initial {
                error!("Packet is not Initial");
                return;
            }
            let mut new_dcid = [0; quiche::MAX_CONN_ID_LEN];
            let new_dcid = &mut new_dcid[0..self.conn_id_len];
            SystemRandom::new().fill(&mut new_dcid[..]).unwrap();

            let new_dcid = quiche::ConnectionId::from_vec(new_dcid.into());

            let mut conn = quiche::accept(
                &new_dcid.clone(),
                None,
                to,
                from,
                &mut self.config,
            )
            .unwrap();

            if let Some(keylog) = &mut self.keylog {
                if let Ok(keylog) = keylog.try_clone() {
                    conn.set_keylog(Box::new(keylog));
                }
            }

            let new_conn_handle = self.next_conn_handle;
            self.conns.insert(
                new_conn_handle,
                QuicConnection {
                    quiche_conn: conn,
                    conn_handle: new_conn_handle,
                    before_established: true,
                    connect_request: None,
                    recv_dgram_readness_requests: VecDeque::new(),
                    send_dgram_requests: VecDeque::new(),
                },
            );
            self.conn_ids.insert(new_dcid, new_conn_handle);
            self.next_conn_handle += 1;
            
            new_conn_handle
        } else {
            *self.conn_ids.get(&hdr.dcid).unwrap()
        };

        let recv_info = quiche::RecvInfo { from, to };
        // Process potentially coalesced packets.
        if let Some(conn) = self.conns.get_mut(&conn_handle) {
            if let Err(e) = conn.quiche_conn.recv(&mut self.buf[..len], recv_info) {
                error!("{} recv() failed: {:?}", conn.quiche_conn.trace_id(), e);
            }

            if conn.quiche_conn.is_established() {
                if conn.before_established {
                    if let Some(request) = conn.connect_request.take() {
                        let _ = request.respond_to.send(Ok(conn_handle));
                    } else {
                        let res = conn.quiche_conn.peer_cert();
                        if self.client_cert_required && res.is_none() {
                            conn.quiche_conn
                                .close(false, 0x1, b"client cert required")
                                .ok();
                        } else {
                            if let Some(request) = self.accept_requests.pop_front() {
                                let _ = request.respond_to.send(Ok(conn_handle));
                            } else {
                                self.wait_conn_handles.push_back(conn_handle);
                            }
                        }
                    }
                    conn.before_established = false;
                }
            }

            if conn.quiche_conn.is_established() {
                if conn.quiche_conn.dgram_recv_queue_len() > 0 {
                    while let Some(request) = conn.recv_dgram_readness_requests.pop_front() {
                        let _ = request.respond_to.send(Ok(()));
                    }
                }
            }

            while let Some(retired_scid) = conn.quiche_conn.retired_scid_next() {
                info!("Retiring source CID: {:?}", retired_scid);
                self.conn_ids.remove(&retired_scid);
            }

            while conn.quiche_conn.source_cids_left() > 0 {
                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                let scid = &mut scid[0..self.conn_id_len];
                SystemRandom::new().fill(&mut scid[..]).unwrap();
                let scid = quiche::ConnectionId::from_vec(scid.into());
                let mut reset_token = [0; 16];
                SystemRandom::new().fill(&mut reset_token).unwrap();
                let reset_token = u128::from_be_bytes(reset_token);

                info!("new_source_cid: {:?} {}", &scid, reset_token);
                if conn.quiche_conn.new_source_cid(&scid, reset_token, false).is_err() {
                    break;
                }
                self.conn_ids.insert(scid, conn.conn_handle);
            }

            while let Some(event) = conn.quiche_conn.path_event_next() {
                info!("PathEvent: {:?}", event);
            }
        }
    }

    async fn run(&mut self) {
        loop {
            let timeout = self
                .conns
                .values()
                .filter_map(|c| c.quiche_conn.timeout())
                .min();

            tokio::select! {
                Ok(_) = self.udp.readable() => {
                    loop {
                        match try_recv_sas(&self.udp, &mut self.buf[..]) {
                            Ok((len, from, to)) => {
                                let to = if to.is_some() {
                                    let mut to = to.unwrap();
                                    to.set_port(self.udp_port);
                                    Some(to)
                                } else {
                                    None
                                };
                                info!("from: {:?}, to: {:?}", from, to);
                                self.handle_udp_dgram(len, from.unwrap(), to).await;
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break;
                            },
                            Err(e) => {
                                error!("try_recv_from() failed: {:?}", e);
                            }
                        }
                    }
                },
                Ok(_) = self.udp6.readable() => {
                    loop {
                        match try_recv_sas(&self.udp6, &mut self.buf[..]) {
                            Ok((len, from, to)) => {
                                let to = if to.is_some() {
                                    let mut to = to.unwrap();
                                    to.set_port(self.udp6_port);
                                    Some(to)
                                } else {
                                    None
                                };
                                self.handle_udp_dgram(len, from.unwrap(), to).await;
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break;
                            },
                            Err(e) => {
                                error!("try_recv_from() failed: {:?}", e);
                            }
                        }
                    }
                },
                maybe_msg = self.receiver.recv(), if !self.shutdown => {
                    if let Some(msg) = maybe_msg {
                        self.handle_message(msg).await;
                    } else {
                        info!("No handle exists!");
                        self.shutdown = true;
                        for conn in self.conns.values_mut() {
                            if !conn.quiche_conn.is_closed() && !conn.quiche_conn.is_draining() {
                                info!("{} Connection closed by shutdown process", conn.quiche_conn.trace_id());
                                conn.quiche_conn.close(false, 0x1, b"shutdown").ok();
                            }
                        }
                    }
                },
                event = Pin::new(&mut self.ifwatcher) => {
                    info!("Got event {:?}", event);
                },
                _ = tokio::time::sleep(timeout.unwrap_or(Duration::from_millis(0))), if timeout.is_some() => {
                    info!("timeout");
                    self.conns.values_mut().for_each(|c| c.quiche_conn.on_timeout());
                }
            }

            for conn in self.conns.values_mut() {
                loop {
                    let (write, send_info) = match conn.quiche_conn.send(&mut self.out) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            break;
                        }
                        Err(e) => {
                            error!("{} send() failed: {:?}", conn.quiche_conn.trace_id(), e);
                            conn.quiche_conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };
                    let udp = if send_info.to.is_ipv4() {
                        &self.udp
                    } else {
                        &self.udp6
                    };
                    match udp.send_to(&self.out[..write], &send_info.to).await {
                        Ok(written) => {
                            trace!("{} written {} bytes", conn.quiche_conn.trace_id(), written);
                        }
                        Err(e) => {
                            error!("{} send_to() failed: {:?}", conn.quiche_conn.trace_id(), e);
                        }
                    }
                }
                if !conn.send_dgram_requests.is_empty() {
                    while let Some(request) = conn.send_dgram_requests.pop_front() {
                        match conn.quiche_conn.dgram_send(&request.buf) {
                            Ok(_) => {
                                let _ = request.respond_to.send(Ok(()));
                            }
                            Err(e) if e == quiche::Error::Done => {
                                conn.send_dgram_requests.push_front(request);
                                break;
                            }
                            Err(e) => {
                                let _ = request.respond_to.send(Err(format!(
                                    "dgram_send failed: {:?}",
                                    e
                                )
                                .into()));
                            }
                        }
                    }
                }
                while let Some(event) = conn.quiche_conn.path_event_next() {
                    info!("event: {:?}", event);
                }
            }

            self.conns.retain(|_, ref mut c| !c.quiche_conn.is_closed());

            self.conn_ids.retain(|_, conn_handle| self.conns.contains_key(conn_handle));

            if self.shutdown && self.conns.is_empty() {
                info!("No connection exists.");
                break;
            }
        }
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        if let Some(request) = self.connect_request.take() {
            let _ = request.respond_to.send(Err("Connection closed".into()));
        }
        for request in self.recv_dgram_readness_requests.drain(..) {
            let _ = request.respond_to.send(Err("Connection closed".into()));
        }
        for request in self.send_dgram_requests.drain(..) {
            let _ = request.respond_to.send(Err("Connection closed".into()));
        }
    }
}

#[derive(Clone)]
pub struct QuicHandle {
    sender: mpsc::Sender<ActorMessage>,
}

impl QuicHandle {
    pub async fn new(
        udp: UdpSocket,
        udp6: UdpSocket,
        config: quiche::Config,
        keylog: Option<File>,
        conn_id_len: usize,
        client_cert_required: bool,
        shutdown_complete: mpsc::Sender<()>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(128);
        let mut actor = QuicActor::new(
            receiver,
            udp,
            udp6,
            config,
            keylog,
            conn_id_len,
            client_cert_required,
            shutdown_complete,
        ).await;
        tokio::spawn(async move { actor.run().await });

        Self { sender }
    }

    pub async fn accept(&self) -> Result<QuicConnectionHandle> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Accept { respond_to: send };
        let _ = self.sender.send(msg).await;
        match recv.await.expect("Actor task has been killed") {
            Ok(conn_handle) => Ok(QuicConnectionHandle {
                sender: self.sender.clone(),
                conn_handle,
            }),
            Err(e) => Err(e),
        }
    }

    pub async fn connect(&self, url: url::Url) -> Result<QuicConnectionHandle> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Connect {
            url,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        match recv.await.expect("Actor task has been killed") {
            Ok(conn_handle) => Ok(QuicConnectionHandle {
                sender: self.sender.clone(),
                conn_handle,
            }),
            Err(e) => Err(e),
        }
    }
}

#[derive(Clone)]
pub struct QuicConnectionHandle {
    sender: mpsc::Sender<ActorMessage>,
    pub conn_handle: ConnectionHandle,
}

impl QuicConnectionHandle {
    pub async fn recv_dgram_ready(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::RecvDgramReadness {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn recv_dgram(&self) -> Result<Option<Bytes>> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = ActorMessage::RecvDgram {
                conn_handle: self.conn_handle,
                respond_to: send,
            };
            let _ = self.sender.send(msg).await;
            match recv.await.expect("Actor task has been killed") {
                Ok(Some(buf)) => {
                    return Ok(Some(buf));
                }
                Ok(None) => {
                    let (send, recv) = oneshot::channel();
                    let msg = ActorMessage::RecvDgramReadness {
                        conn_handle: self.conn_handle,
                        respond_to: send,
                    };
                    let _ = self.sender.send(msg).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    pub async fn recv_dgram_vectored(&self, max_len: usize) -> Result<Vec<Bytes>> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = ActorMessage::RecvDgramVectored {
                conn_handle: self.conn_handle,
                max_len,
                respond_to: send,
            };
            let _ = self.sender.send(msg).await;
            match recv.await.expect("Actor task has been killed") {
                Ok(bufs) => {
                    if !bufs.is_empty() {
                        return Ok(bufs);
                    }
                    let (send, recv) = oneshot::channel();
                    let msg = ActorMessage::RecvDgramReadness {
                        conn_handle: self.conn_handle,
                        respond_to: send,
                    };
                    let _ = self.sender.send(msg).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    pub async fn recv_dgram_info(&self) -> Result<(Option<usize>, usize, usize)> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::RecvDgramInfo {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn send_dgram(&self, buf: &Bytes) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::SendDgram {
            conn_handle: self.conn_handle,
            buf: buf.clone(),
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn stats(&self) -> Result<quiche::Stats> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Stats {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn close(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = ActorMessage::Close {
            conn_handle: self.conn_handle,
            respond_to: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}

pub mod testing {
    use super::*;

    pub async fn open_server(
        port: u16,
        shutdown_complete_tx: mpsc::Sender<()>,
    ) -> Result<QuicHandle> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.load_cert_chain_from_pem_file("src/cert.crt")?;
        config.load_priv_key_from_pem_file("src/cert.key")?;
        config.set_application_protos(&[b"proto1"])?;
        config.set_max_idle_timeout(10000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.enable_dgram(true, 1000, 1000);

        let udp = tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port)).await?;
        let udp6 = tokio::net::UdpSocket::bind(format!("[::1]:{}", port)).await?;
        let quic = QuicHandle::new(
            udp,
            udp6,
            config,
            None,
            quiche::MAX_CONN_ID_LEN,
            false,
            shutdown_complete_tx.clone(),
        ).await;
        Ok(quic)
    }

    pub async fn open_client(shutdown_complete_tx: mpsc::Sender<()>) -> Result<QuicHandle> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.set_application_protos(&[b"proto1"])?;
        config.verify_peer(false);
        config.set_max_idle_timeout(10000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_early_data();
        config.enable_dgram(true, 1000, 1000);

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let udp6 = tokio::net::UdpSocket::bind("[::1]:0").await?;
        let quic = QuicHandle::new(
            udp,
            udp6,
            config,
            None,
            quiche::MAX_CONN_ID_LEN,
            false,
            shutdown_complete_tx.clone(),
        ).await;
        Ok(quic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_v4() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let _server = testing::open_server(12345, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone())
            .await
            .unwrap();
        let url = url::Url::parse("http://127.0.0.1:12345").unwrap();
        let ret = client.connect(url).await;
        assert_eq!(ret.is_ok(), true);
    }

    #[tokio::test]
    async fn connect_v6() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let _server = testing::open_server(12346, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone())
            .await
            .unwrap();
        let url = url::Url::parse("http://[::1]:12346").unwrap();
        let ret = client.connect(url).await;
        assert_eq!(ret.is_ok(), true);
    }

    #[tokio::test]
    async fn accept_v4() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let server = testing::open_server(12347, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone())
            .await
            .unwrap();
        let url = url::Url::parse("http://127.0.0.1:12347").unwrap();
        let _ = client.connect(url).await;
        let ret = server.accept().await;
        assert_eq!(ret.is_ok(), true);
    }

    #[tokio::test]
    async fn accept_v6() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let server = testing::open_server(12348, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone())
            .await
            .unwrap();
        let url = url::Url::parse("http://[::1]:12348").unwrap();
        let _ = client.connect(url).await;
        let ret = server.accept().await;
        assert_eq!(ret.is_ok(), true);
    }

    #[tokio::test]
    async fn dgram() {
        let (shutdown_complete_tx, _) = mpsc::channel(1);
        let server = testing::open_server(12349, shutdown_complete_tx.clone())
            .await
            .unwrap();
        let client = testing::open_client(shutdown_complete_tx.clone())
            .await
            .unwrap();
        let url = url::Url::parse("http://127.0.0.1:12349").unwrap();
        let conn = client.connect(url).await.unwrap();
        let conn1 = server.accept().await.unwrap();

        let buf = Bytes::from("hello");
        conn.send_dgram(&buf).await.unwrap();
        let ret = conn1.recv_dgram().await;
        assert_eq!(ret.is_ok(), true);
        let buf1 = ret.unwrap();
        assert_eq!(buf1.is_some(), true);
        if let Some(buf1) = buf1 {
            assert_eq!(buf, buf1);
        }
    }
}
