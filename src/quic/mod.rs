pub mod buf_read_dgram;

use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{Stream, StreamExt, StreamMap};

use ring::rand::*;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::sas::{bind_sas, select_local_addr, send_sas, try_recv_sas};

pub use self::buf_read_dgram::BufReadDgram;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

type SocketHandle = usize;
type SocketMap = HashMap<SocketHandle, Arc<UdpSocket>>;
type ConnectionHandle = u64;

struct QuicActor {
    receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
    next_socket_handle: SocketHandle,
    sockets: SocketMap,
    recv_stream:
        StreamMap<usize, Pin<Box<dyn Stream<Item = (BytesMut, SocketAddr, SocketAddr)> + Send>>>,
    dgram_read_stream: StreamMap<ConnectionHandle, Pin<Box<dyn Stream<Item = bool> + Send>>>,
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
    out: Vec<u8>,
    _shutdown_complete: mpsc::Sender<()>,
}

#[derive(Debug)]
pub(crate) enum Request {
    Accept,
    Listen {
        local: SocketAddr,
    },
    Connect {
        url: url::Url,
    },
    OpenBufReadDgram {
        conn_handle: ConnectionHandle,
        capacity: usize,
    },
    RecvDgramReadness {
        conn_handle: ConnectionHandle,
    },
    RecvDgram {
        conn_handle: ConnectionHandle,
    },
    RecvDgramVectored {
        conn_handle: ConnectionHandle,
        max_len: usize,
    },
    RecvDgramInfo {
        conn_handle: ConnectionHandle,
    },
    SendDgram {
        conn_handle: ConnectionHandle,
        buf: Bytes,
    },
    Stats {
        conn_handle: ConnectionHandle,
    },
    Close {
        conn_handle: ConnectionHandle,
    },
    PathStats {
        conn_handle: ConnectionHandle,
    },
}

#[derive(Debug)]
pub(crate) enum Response {
    Accept(Result<ConnectionHandle>),
    Listen(Result<()>),
    Connect(Result<ConnectionHandle>),
    OpenBufReadDgram(Result<BufReadDgram>),
    RecvDgramReadness(Result<()>),
    RecvDgram(Result<Option<Bytes>>),
    RecvDgramVectored(Result<Vec<Bytes>>),
    RecvDgramInfo(Result<(Option<usize>, usize, usize)>),
    SendDgram(Result<()>),
    Stats(Result<quiche::Stats>),
    Close(Result<()>),
    PathStats(Result<Vec<quiche::PathStats>>),
}

struct QuicConnection {
    quiche_conn: quiche::Connection,
    socket: Arc<UdpSocket>,
    before_established: bool,
    connect_request: Option<ConnectRequest>,
    recv_dgram_readness_requests: VecDeque<RecvDgramReadnessRequest>,
    send_dgram_requests: VecDeque<SendDgramRequest>,
    read_dgram_sender: Option<mpsc::Sender<Bytes>>,
}
type QuicConnectionIdMap = HashMap<quiche::ConnectionId<'static>, ConnectionHandle>;
type QuicConnectionMap = HashMap<ConnectionHandle, QuicConnection>;

struct AcceptRequest {
    respond_to: oneshot::Sender<Response>,
}

struct ConnectRequest {
    respond_to: oneshot::Sender<Response>,
}

struct RecvDgramReadnessRequest {
    respond_to: oneshot::Sender<Response>,
}

struct SendDgramRequest {
    buf: Bytes,
    respond_to: oneshot::Sender<Response>,
}

impl QuicActor {
    fn new(
        receiver: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
        config: quiche::Config,
        keylog: Option<File>,
        conn_id_len: usize,
        client_cert_required: bool,
        shutdown_complete: mpsc::Sender<()>,
    ) -> Self {
        QuicActor {
            receiver,
            next_socket_handle: 0,
            sockets: SocketMap::new(),
            recv_stream: StreamMap::new(),
            dgram_read_stream: StreamMap::new(),
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
            out: vec![0; 1350],
            _shutdown_complete: shutdown_complete,
        }
    }

    async fn add_socket(&mut self, local: SocketAddr) -> std::io::Result<SocketHandle> {
        let socket = bind_sas(&local).await?;
        let socket: socket2::Socket = socket.into_std().unwrap().into();
        socket.set_recv_buffer_size(0x7fffffff).unwrap();
        let socket: std::net::UdpSocket = socket.into();
        let socket = Arc::new(tokio::net::UdpSocket::from_std(socket).unwrap());

        let socket_handle = self.next_socket_handle;
        self.sockets.insert(socket_handle, socket.clone());
        self.next_socket_handle += 1;

        let stream = Box::pin(async_stream::stream! {
            'outer: loop {
                if socket.readable().await.is_ok() {
                    'inner: loop {
                        let mut buf = BytesMut::with_capacity(2048);
                        buf.resize(2048, 0);
                        match try_recv_sas(&socket, &mut buf[..]) {
                            Ok((len, from, to)) => {
                                buf.truncate(len);
                                let from = from.unwrap();
                                let to = if to.is_some() {
                                    let mut to = to.unwrap();
                                    to.set_port(local.port());
                                    to
                                } else {
                                    local
                                };
                                info!("from: {:?}, to: {:?}", from, to);
                                yield((buf, from, to));
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                break 'inner;
                            },
                            Err(e) => {
                                error!("try_recv_from() failed: {:?}", e);
                                break 'outer;
                            }
                        }
                    }
                }
            }
        })
            as Pin<Box<dyn Stream<Item = (BytesMut, SocketAddr, SocketAddr)> + Send>>;
        self.recv_stream.insert(socket_handle, stream);
        Ok(socket_handle)
    }

    async fn handle_message(&mut self, msg: Request, respond_to: oneshot::Sender<Response>) {
        match msg {
            Request::Accept => self.handle_accept_request(respond_to).await,
            Request::Listen { local } => self.handle_listen_request(local, respond_to).await,
            Request::Connect { url } => self.handle_connect_request(url, respond_to).await,
            Request::OpenBufReadDgram {
                conn_handle,
                capacity,
            } => {
                self.handle_open_buf_read_dgram_request(conn_handle, capacity, respond_to)
                    .await
            }
            Request::RecvDgramReadness { conn_handle } => {
                self.handle_recv_dgram_readness_request(conn_handle, respond_to)
                    .await
            }
            Request::RecvDgram { conn_handle } => {
                self.handle_recv_dgram_request(conn_handle, respond_to)
                    .await
            }
            Request::RecvDgramVectored {
                conn_handle,
                max_len,
            } => {
                self.handle_recv_dgram_vectored_request(conn_handle, max_len, respond_to)
                    .await
            }
            Request::RecvDgramInfo { conn_handle } => {
                self.handle_recv_dgram_info_request(conn_handle, respond_to)
                    .await
            }
            Request::SendDgram { conn_handle, buf } => {
                self.handle_send_dgram_request(conn_handle, buf, respond_to)
                    .await
            }
            Request::Stats { conn_handle } => {
                self.handle_stats_request(conn_handle, respond_to).await
            }
            Request::PathStats { conn_handle } => {
                self.handle_path_stats_request(conn_handle, respond_to)
                    .await
            }
            Request::Close { conn_handle } => {
                self.handle_close_request(conn_handle, respond_to).await
            }
        }
    }

    async fn handle_accept_request(&mut self, respond_to: oneshot::Sender<Response>) {
        if let Some(conn_handle) = self.wait_conn_handles.pop_front() {
            let response = Response::Accept(Ok(conn_handle));
            let _ = respond_to.send(response);
        } else {
            self.accept_requests.push_back(AcceptRequest { respond_to });
        }
    }

    async fn handle_listen_request(
        &mut self,
        local: SocketAddr,
        respond_to: oneshot::Sender<Response>,
    ) {
        let response = match self.add_socket(local).await {
            Ok(_) => Response::Listen(Ok(())),
            Err(e) => Response::Listen(Err(format!("add_socket failed: {:?}", e).into())),
        };
        let _ = respond_to.send(response);
    }

    async fn handle_connect_request(
        &mut self,
        url: url::Url,
        respond_to: oneshot::Sender<Response>,
    ) {
        let to = url.to_socket_addrs().unwrap().next().unwrap();
        let from = select_local_addr(to, None).await.unwrap();
        let local = if to.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), from.port())
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), from.port())
        };
        let socket_handle = match self.add_socket(local).await {
            Ok(v) => v,
            Err(e) => {
                let response =
                    Response::Connect(Err(format!("get_binding failed: {:?}", e).into()));
                let _ = respond_to.send(response);
                return;
            }
        };
        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let scid = &mut scid[0..self.conn_id_len];
        ring::rand::SystemRandom::new().fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid).into_owned();
        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(url.domain(), &scid, from, to, &mut self.config).unwrap();

        if let Some(keylog) = &self.keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let writer = make_qlog_writer(&dir, "client", &conn.trace_id());

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", conn.trace_id()),
            );
        }

        let (write, send_info) = conn.send(&mut self.out).expect("initial send failed");

        let socket = self.sockets.get(&socket_handle).unwrap();
        let _written = send_sas(socket, &self.out[..write], &send_info.to, &send_info.from)
            .await
            .unwrap();

        self.conns.insert(
            self.next_conn_handle,
            QuicConnection {
                quiche_conn: conn,
                socket: socket.clone(),
                before_established: true,
                connect_request: Some(ConnectRequest { respond_to }),
                recv_dgram_readness_requests: VecDeque::new(),
                send_dgram_requests: VecDeque::new(),
                read_dgram_sender: None,
            },
        );
        self.conn_ids.insert(scid, self.next_conn_handle);
        self.next_conn_handle += 1;
    }

    async fn handle_open_buf_read_dgram_request(
        &mut self,
        conn_handle: u64,
        capacity: usize,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::OpenBufReadDgram(Err(
                        format!("No Connection: {:?}", conn_handle).into()
                    ));
                let _ = respond_to.send(response);
                return;
            }
        };

        let (sender, receiver) = mpsc::channel(capacity);
        let buf_read_dgram = BufReadDgram::new(receiver);
        conn.read_dgram_sender = Some(sender);
        let response = Response::OpenBufReadDgram(Ok(buf_read_dgram));
        let _ = respond_to.send(response);
    }

    async fn handle_recv_dgram_readness_request(
        &mut self,
        conn_handle: u64,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::RecvDgramReadness(Err(
                        format!("No Connection: {:?}", conn_handle).into()
                    ));
                let _ = respond_to.send(response);
                return;
            }
        };

        if conn.quiche_conn.dgram_recv_queue_len() > 0 {
            let response = Response::RecvDgramReadness(Ok(()));
            let _ = respond_to.send(response);
        } else {
            conn.recv_dgram_readness_requests
                .push_back(RecvDgramReadnessRequest { respond_to });
        }
    }

    async fn handle_recv_dgram_request(
        &mut self,
        conn_handle: u64,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::RecvDgram(Err(format!("No Connection: {:?}", conn_handle).into()));
                let _ = respond_to.send(response);
                return;
            }
        };

        if conn.quiche_conn.dgram_recv_queue_len() == 0 {
            let response = Response::RecvDgram(Ok(None));
            let _ = respond_to.send(response);
            return;
        }

        let mut buf = BytesMut::with_capacity(1350);
        buf.resize(1350, 0);
        let response = match conn.quiche_conn.dgram_recv(&mut buf) {
            Ok(len) => {
                buf.truncate(len);
                Response::RecvDgram(Ok(Some(buf.freeze())))
            }
            Err(e) if e == quiche::Error::Done => Response::RecvDgram(Ok(None)),
            Err(e) => Response::RecvDgram(Err(format!("dgram_recv failed: {:?}", e).into())),
        };

        let _ = respond_to.send(response);
    }

    async fn handle_recv_dgram_vectored_request(
        &mut self,
        conn_handle: u64,
        max_len: usize,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::RecvDgramVectored(Err(
                        format!("No Connection: {:?}", conn_handle).into()
                    ));
                let _ = respond_to.send(response);
                return;
            }
        };

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

        let response = Response::RecvDgramVectored(Ok(bufs));
        let _ = respond_to.send(response);
    }

    async fn handle_recv_dgram_info_request(
        &mut self,
        conn_handle: u64,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::RecvDgramInfo(
                        Err(format!("No Connection: {:?}", conn_handle).into()),
                    );
                let _ = respond_to.send(response);
                return;
            }
        };

        let front_len = conn.quiche_conn.dgram_recv_front_len();
        let queue_byte_size = conn.quiche_conn.dgram_recv_queue_byte_size();
        let queue_len = conn.quiche_conn.dgram_recv_queue_len();

        let response = Response::RecvDgramInfo(Ok((front_len, queue_byte_size, queue_len)));
        let _ = respond_to.send(response);
    }

    async fn handle_send_dgram_request(
        &mut self,
        conn_handle: u64,
        buf: Bytes,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::SendDgram(Err(format!("No Connection: {:?}", conn_handle).into()));
                let _ = respond_to.send(response);
                return;
            }
        };

        let response = match conn.quiche_conn.dgram_send(&buf) {
            Ok(_) => Response::SendDgram(Ok(())),
            Err(e) if e == quiche::Error::Done => {
                conn.send_dgram_requests
                    .push_back(SendDgramRequest { buf, respond_to });
                return;
            }
            Err(e) => Response::SendDgram(Err(format!("dgram_send failed: {:?}", e).into())),
        };

        let _ = respond_to.send(response);
    }

    async fn handle_stats_request(
        &mut self,
        conn_handle: u64,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::Stats(Err(format!("No Connection: {:?}", conn_handle).into()));
                let _ = respond_to.send(response);
                return;
            }
        };

        let stats = conn.quiche_conn.stats();
        let response = Response::Stats(Ok(stats));
        let _ = respond_to.send(response);
    }

    async fn handle_path_stats_request(
        &mut self,
        conn_handle: u64,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::PathStats(Err(format!("No Connection: {:?}", conn_handle).into()));
                let _ = respond_to.send(response);
                return;
            }
        };

        let stats = conn
            .quiche_conn
            .path_stats()
            .collect::<Vec<quiche::PathStats>>();

        let response = Response::PathStats(Ok(stats));
        let _ = respond_to.send(response);
    }

    async fn handle_close_request(
        &mut self,
        conn_handle: u64,
        respond_to: oneshot::Sender<Response>,
    ) {
        let conn = match self.conns.get_mut(&conn_handle) {
            Some(conn) => conn,
            None => {
                let response =
                    Response::Close(Err(format!("No Connection: {:?}", conn_handle).into()));
                let _ = respond_to.send(response);
                return;
            }
        };

        conn.quiche_conn.close(true, 0x00, b"").ok();
        let response = Response::Close(Ok(()));
        let _ = respond_to.send(response);
    }

    async fn handle_udp_dgram(
        &mut self,
        handle: SocketHandle,
        mut buf: BytesMut,
        from: SocketAddr,
        to: SocketAddr,
    ) {
        trace!("Recv UDP {} bytes", buf.len());

        let hdr = match quiche::Header::from_slice(&mut buf, quiche::MAX_CONN_ID_LEN) {
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

            let mut conn = quiche::accept(&new_dcid, None, to, from, &mut self.config).unwrap();

            if let Some(keylog) = &mut self.keylog {
                if let Ok(keylog) = keylog.try_clone() {
                    conn.set_keylog(Box::new(keylog));
                }
            }

            if let Some(dir) = std::env::var_os("QLOGDIR") {
                let writer = make_qlog_writer(&dir, "server", &conn.trace_id());

                conn.set_qlog(
                    std::boxed::Box::new(writer),
                    "quiche-server qlog".to_string(),
                    format!("{} id={}", "quiche-server qlog", conn.trace_id()),
                );
            }

            let socket = self.sockets.get(&handle).unwrap();
            let new_conn_handle = self.next_conn_handle;

            self.conns.insert(
                new_conn_handle,
                QuicConnection {
                    quiche_conn: conn,
                    socket: socket.clone(),
                    before_established: true,
                    connect_request: None,
                    recv_dgram_readness_requests: VecDeque::new(),
                    send_dgram_requests: VecDeque::new(),
                    read_dgram_sender: None,
                },
            );
            self.conn_ids.insert(new_dcid.clone(), new_conn_handle);
            self.next_conn_handle += 1;

            new_conn_handle
        } else {
            *self.conn_ids.get(&hdr.dcid).unwrap()
        };

        let recv_info = quiche::RecvInfo { from, to };
        // Process potentially coalesced packets.
        if let Some(conn) = self.conns.get_mut(&conn_handle) {
            if let Err(e) = conn.quiche_conn.recv(&mut buf, recv_info) {
                error!("{} recv() failed: {:?}", conn.quiche_conn.trace_id(), e);
            }

            if conn.quiche_conn.is_established() {
                if conn.before_established {
                    if let Some(request) = conn.connect_request.take() {
                        // Client case
                        let response = Response::Connect(Ok(conn_handle));
                        let _ = request.respond_to.send(response);
                    } else {
                        // Server case
                        let res = conn.quiche_conn.peer_cert();
                        if self.client_cert_required && res.is_none() {
                            conn.quiche_conn
                                .close(false, 0x1, b"client cert required")
                                .ok();
                        } else {
                            if let Some(request) = self.accept_requests.pop_front() {
                                let response = Response::Accept(Ok(conn_handle));
                                let _ = request.respond_to.send(response);
                            } else {
                                self.wait_conn_handles.push_back(conn_handle);
                            }
                        }
                    }
                    conn.before_established = false;
                }
            }

            if conn.quiche_conn.is_established() {
                if let Some(sender) = &conn.read_dgram_sender {
                    while conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        if let Ok(permit) = sender.try_reserve() {
                            let len = conn.quiche_conn.dgram_recv_front_len().unwrap();
                            let mut buf = BytesMut::with_capacity(len);
                            buf.resize(len, 0);
                            conn.quiche_conn.dgram_recv(&mut buf).unwrap();
                            permit.send(buf.freeze());
                        } else {
                            if !self.dgram_read_stream.contains_key(&conn_handle) {
                                let new_sender = sender.clone();
                                let stream = Box::pin(async_stream::stream! {
                                    loop {
                                        if new_sender.reserve().await.is_ok() {
                                            yield true;
                                        } else {
                                            yield false;
                                        }
                                    }
                                })
                                    as Pin<Box<dyn Stream<Item = bool> + Send>>;
                                self.dgram_read_stream.insert(conn_handle, stream);
                            }
                            break;
                        }
                    }
                } else {
                    if conn.quiche_conn.dgram_recv_queue_len() > 0 {
                        while let Some(request) = conn.recv_dgram_readness_requests.pop_front() {
                            let response = Response::RecvDgramReadness(Ok(()));
                            let _ = request.respond_to.send(response);
                        }
                    }
                }
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
                if conn
                    .quiche_conn
                    .new_source_cid(&scid, reset_token, false)
                    .is_err()
                {
                    break;
                }
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
                Some((handle, (buf, from, to))) = self.recv_stream.next() => {
                    self.handle_udp_dgram(handle, buf, from, to).await;
                }
                maybe_msg = self.receiver.recv(), if !self.shutdown => {
                    if let Some((msg, respond_to)) = maybe_msg {
                        self.handle_message(msg, respond_to).await;
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
                Some((conn_handle, available)) = self.dgram_read_stream.next() => {
                    if let Some(conn) = self.conns.get_mut(&conn_handle) {
                        if available {
                            let mut will_remove = false;
                            let mut dropped = false;

                            if let Some(sender) = &conn.read_dgram_sender {
                                while conn.quiche_conn.dgram_recv_queue_len() > 0 {
                                    match sender.try_reserve() {
                                        Ok(permit) => {
                                            let len = conn.quiche_conn.dgram_recv_front_len().unwrap();
                                            let mut buf = BytesMut::with_capacity(len);
                                            buf.resize(len, 0);
                                            conn.quiche_conn.dgram_recv(&mut buf).unwrap();
                                            permit.send(buf.freeze());
                                        }
                                        Err(mpsc::error::TrySendError::Full(_)) => {
                                            break;
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => {
                                            // BufReadDgram dropped.
                                            dropped = true;
                                            will_remove = true;
                                            break;
                                        }
                                    }
                                }
                                if conn.quiche_conn.dgram_recv_queue_len() == 0 {
                                    will_remove = true;
                                }
                            } else {
                                will_remove = true;
                            }
                            if dropped {
                                conn.read_dgram_sender = None;
                            }
                            if will_remove {
                                self.dgram_read_stream.remove(&conn_handle);
                            }
                        } else {
                            // BufReadDgram dropped?
                            conn.read_dgram_sender = None;
                            self.dgram_read_stream.remove(&conn_handle);
                        }
                    } else {
                        // No connection
                        self.dgram_read_stream.remove(&conn_handle);
                    }
                }
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
                    match send_sas(
                        &conn.socket,
                        &self.out[..write],
                        &send_info.to,
                        &send_info.from,
                    )
                    .await
                    {
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
                                let response = Response::SendDgram(Ok(()));
                                let _ = request.respond_to.send(response);
                            }
                            Err(e) if e == quiche::Error::Done => {
                                conn.send_dgram_requests.push_front(request);
                                break;
                            }
                            Err(e) => {
                                let response =
                                    Response::SendDgram(Err(
                                        format!("dgram_send failed: {:?}", e).into()
                                    ));
                                let _ = request.respond_to.send(response);
                            }
                        }
                    }
                }
                while let Some(event) = conn.quiche_conn.path_event_next() {
                    info!("event: {:?}", event);
                }
            }
            self.conns.retain(|_, ref mut c| !c.quiche_conn.is_closed());

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
            let response = Response::Connect(Err("Connection closed".into()));
            let _ = request.respond_to.send(response);
        }
        for request in self.recv_dgram_readness_requests.drain(..) {
            let response = Response::RecvDgramReadness(Err("Connection closed".into()));
            let _ = request.respond_to.send(response);
        }
        for request in self.send_dgram_requests.drain(..) {
            let response = Response::SendDgram(Err("Connection closed".into()));
            let _ = request.respond_to.send(response);
        }
    }
}

#[derive(Clone)]
pub struct QuicHandle {
    sender: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl QuicHandle {
    pub fn new(
        config: quiche::Config,
        keylog: Option<File>,
        conn_id_len: usize,
        client_cert_required: bool,
        shutdown_complete: mpsc::Sender<()>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(128);
        let mut actor = QuicActor::new(
            receiver,
            config,
            keylog,
            conn_id_len,
            client_cert_required,
            shutdown_complete,
        );

        tokio::spawn(async move { actor.run().await });

        Self { sender }
    }

    pub async fn listen(&self, local: SocketAddr) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = Request::Listen { local };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::Listen(Ok(v)) => Ok(v),
            Response::Listen(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn accept(&self) -> Result<QuicConnectionHandle> {
        let (send, recv) = oneshot::channel();
        let msg = Request::Accept;
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::Accept(Ok(conn_handle)) => Ok(QuicConnectionHandle {
                sender: self.sender.clone(),
                conn_handle,
            }),
            Response::Accept(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn connect(&self, url: url::Url) -> Result<QuicConnectionHandle> {
        let (send, recv) = oneshot::channel();
        let msg = Request::Connect { url };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::Connect(Ok(conn_handle)) => Ok(QuicConnectionHandle {
                sender: self.sender.clone(),
                conn_handle,
            }),
            Response::Connect(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }
}

#[derive(Clone)]
pub struct QuicConnectionHandle {
    sender: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
    pub conn_handle: ConnectionHandle,
}

impl QuicConnectionHandle {
    pub async fn recv_dgram_ready(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = Request::RecvDgramReadness {
            conn_handle: self.conn_handle,
        };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::RecvDgramReadness(Ok(v)) => Ok(v),
            Response::RecvDgramReadness(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn recv_dgram(&self) -> Result<Option<Bytes>> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = Request::RecvDgram {
                conn_handle: self.conn_handle,
            };
            let _ = self.sender.send((msg, send)).await;
            match recv.await.expect("Actor task has been killed") {
                Response::RecvDgram(Ok(Some(buf))) => {
                    return Ok(Some(buf));
                }
                Response::RecvDgram(Ok(None)) => {
                    let (send, recv) = oneshot::channel();
                    let msg = Request::RecvDgramReadness {
                        conn_handle: self.conn_handle,
                    };
                    let _ = self.sender.send((msg, send)).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Response::RecvDgram(Err(e)) => {
                    return Err(e);
                }
                v => {
                    return Err(format!("Invalid Response: {:?}", v).into());
                }
            }
        }
    }

    pub async fn recv_dgram_vectored(&self, max_len: usize) -> Result<Vec<Bytes>> {
        loop {
            let (send, recv) = oneshot::channel();
            let msg = Request::RecvDgramVectored {
                conn_handle: self.conn_handle,
                max_len,
            };
            let _ = self.sender.send((msg, send)).await;
            match recv.await.expect("Actor task has been killed") {
                Response::RecvDgramVectored(Ok(bufs)) => {
                    if !bufs.is_empty() {
                        return Ok(bufs);
                    }
                    let (send, recv) = oneshot::channel();
                    let msg = Request::RecvDgramReadness {
                        conn_handle: self.conn_handle,
                    };
                    let _ = self.sender.send((msg, send)).await;
                    let _ = recv.await.expect("Actor task has been killed");
                }
                Response::RecvDgramVectored(Err(e)) => {
                    return Err(e);
                }
                v => {
                    return Err(format!("Invalid Response: {:?}", v).into());
                }
            }
        }
    }

    pub async fn recv_dgram_info(&self) -> Result<(Option<usize>, usize, usize)> {
        let (send, recv) = oneshot::channel();
        let msg = Request::RecvDgramInfo {
            conn_handle: self.conn_handle,
        };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::RecvDgramInfo(Ok(v)) => Ok(v),
            Response::RecvDgramInfo(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn open_buf_read_dgram(&self, capacity: usize) -> Result<BufReadDgram> {
        let (send, recv) = oneshot::channel();
        let msg = Request::OpenBufReadDgram {
            conn_handle: self.conn_handle,
            capacity,
        };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::OpenBufReadDgram(Ok(v)) => Ok(v),
            Response::OpenBufReadDgram(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn send_dgram(&self, buf: &Bytes) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = Request::SendDgram {
            conn_handle: self.conn_handle,
            buf: buf.clone(),
        };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::SendDgram(Ok(v)) => Ok(v),
            Response::SendDgram(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn stats(&self) -> Result<quiche::Stats> {
        let (send, recv) = oneshot::channel();
        let msg = Request::Stats {
            conn_handle: self.conn_handle,
        };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::Stats(Ok(v)) => Ok(v),
            Response::Stats(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn path_stats(&self) -> Result<Vec<quiche::PathStats>> {
        let (send, recv) = oneshot::channel();
        let msg = Request::PathStats {
            conn_handle: self.conn_handle,
        };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::PathStats(Ok(v)) => Ok(v),
            Response::PathStats(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }

    pub async fn close(&self) -> Result<()> {
        let (send, recv) = oneshot::channel();
        let msg = Request::Close {
            conn_handle: self.conn_handle,
        };
        let _ = self.sender.send((msg, send)).await;
        match recv.await.expect("Actor task has been killed") {
            Response::Close(Ok(v)) => Ok(v),
            Response::Close(Err(e)) => Err(e),
            v => Err(format!("Invalid Response: {:?}", v).into()),
        }
    }
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer(
    dir: &std::ffi::OsStr,
    role: &str,
    id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{}-{}.sqlog", role, id);
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
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

        let quic = QuicHandle::new(
            config,
            None,
            quiche::MAX_CONN_ID_LEN,
            false,
            shutdown_complete_tx.clone(),
        );

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
        quic.listen(local).await.unwrap();
        let local = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port);
        quic.listen(local).await.unwrap();
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

        let quic = QuicHandle::new(
            config,
            None,
            quiche::MAX_CONN_ID_LEN,
            false,
            shutdown_complete_tx.clone(),
        );
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
