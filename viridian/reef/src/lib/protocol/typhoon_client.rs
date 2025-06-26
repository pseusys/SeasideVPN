use std::cmp::max;
use std::mem::replace;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::u32;

use log::{debug, info, warn};
use rand::Rng;
use simple_error::bail;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::{pin, select};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::bytes::{get_buffer, ByteBuffer};
use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::common::{ProtocolFlag, ProtocolMessageType};
use crate::rng::get_rng;
use crate::{run_coroutine_in_thread, run_coroutine_sync};
use crate::{DynResult, Reader, Writer};
use super::typhoon_core::*;


#[inline]
fn get_timestamp() -> u32 {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
    (time % u32::MAX as u128) as u32
}

#[inline]
fn generate_next_in(multiplier: f32) -> u32 {
    (get_rng().gen_range(*TYPHOON_MIN_NEXT_IN..=*TYPHOON_MAX_NEXT_IN) as f32 * multiplier) as u32
}


pub struct TyphoonHandle<'a> {
    peer_address: SocketAddr,
    asymmetric: Asymmetric,
    local: SocketAddr,
    token: ByteBuffer<'a>
}

impl <'a> TyphoonHandle<'a> {
    async fn read_server_init(&self, socket: &UdpSocket, cipher: &mut Symmetric, packet_number: u32) -> DynResult<(u16, u32)> {
        debug!("Reading server initialization message...");
        loop {
            let buffer = get_buffer(None).await;
            let size = match socket.recv(&mut buffer.slice_mut()).await {
                Ok(res) => {
                    debug!("Received initialization packet of size: {res}");
                    res
                },
                Err(err) => {
                    warn!("Invalid packet read error: {err}");
                    continue;
                }
            };
            let (user_id, next_in) = match parse_server_init(cipher, buffer.rebuffer_end(size), packet_number).await {
                Ok(res) => res,
                Err(err) => {
                    warn!("Peer packet parsing error: {err}");
                    continue;
                }
            };
            debug!("Server initialization message received: user ID {user_id}, next in {next_in}");
            return Ok((user_id, next_in))
        }
    }

    async fn connect_inner(&mut self, socket: &UdpSocket) -> DynResult<(u16, u32, Symmetric)> {
        let mut packet_number: u32;
    
        for i in 0..*TYPHOON_MAX_RETRIES {
            debug!("Trying connection attempt {i}...");
            packet_number = get_timestamp();
            let next_in = generate_next_in(*TYPHOON_INITIAL_NEXT_IN);

            debug!("Sending initialization packet with: packet number {packet_number} and next in {next_in}...");
            let (mut symmetric, packet) = build_client_init(&self.asymmetric, packet_number, next_in, &self.token).await?;
            socket.send(&packet.slice()).await?;
            let sleep = next_in + (*TYPHOON_DEFAULT_TIMEOUT).clamp(*TYPHOON_MIN_TIMEOUT, *TYPHOON_MAX_TIMEOUT);

            debug!("Waiting for server response for {sleep} milliseconds...");
            match timeout(Duration::from_millis(sleep as u64), self.read_server_init(socket, &mut symmetric, packet_number)).await {
                Ok(Ok((user_id, next_in))) => return Ok((user_id, next_in, symmetric)),
                Ok(Err(err)) => warn!("Error while parsing server response: {err}"),
                Err(_) => info!("Peer packet waiting timeout, retrying...")
            }
        }

        bail!("Connection could not be established (maximum retries reached)!")
    }

    #[allow(refining_impl_trait)]
    pub fn new(key: ByteBuffer<'_>, token: ByteBuffer<'a>, address: Ipv4Addr, port: u16, local: Ipv4Addr) -> DynResult<Self> {
        debug!("Creating TYPHOON protocol handle...");
        let peer_address = SocketAddr::new(IpAddr::V4(address), port);
        let local_address = SocketAddr::new(IpAddr::V4(local), 0);
        debug!("Handle set up to connect {local_address} (local) to {peer_address} (caerulean)!");
        Ok(Self {
            peer_address: peer_address,
            asymmetric: Asymmetric::new(&key)?,
            local: local_address,
            token
        })
    }

    pub async fn connect(&mut self) -> DynResult<impl Reader + Writer + Clone> {
        debug!("Binding connection client to {}...", self.local);
        let socket = UdpSocket::bind(self.local).await?;

        debug!("Connecting to listener at {}", self.peer_address);
        socket.connect(&self.peer_address).await?;
        debug!("Current user address: {}", socket.local_addr()?);

        let (user_id, next_in, cipher) = self.connect_inner(&socket).await?;
        info!("Discovered server at {}", socket.peer_addr()?);

        let mut main_address = self.peer_address.clone();
        main_address.set_port(user_id);
        socket.connect(main_address).await?;
        info!("Connected to the server at {}", socket.peer_addr()?);

        let (term_sender, term_receiver) = channel(1);
        let (ctrl_sender, ctrl_receiver) = channel(1);
        let (decay_sender, decay_receiver) = channel(1);
        let client = TyphoonClient {
            keeper: true,
            internal: Arc::new(TyphoonClientImmutable {
                socket,
                references: AtomicUsize::new(0),
                internal: RwLock::new(TyphoonClientMutable {
                    termination_channel: term_sender,
                    control_channel: ctrl_receiver,
                    decay_channel: decay_sender,
                    prev_packet_number: None,
                    prev_next_in: 0,
                    prev_sent: 0,
                    rttvar: None,
                    srtt: None,
                    decay: None
                })
            }),
            symmetric: cipher
        };

        let mut client_clone = client.clone();
        client_clone.keeper = false;
        let decay = run_coroutine_in_thread!(client_clone.decay_cycle(next_in, ctrl_sender, decay_receiver, term_receiver));
        client.internal.references.fetch_sub(1, Ordering::SeqCst);
        client.internal.internal.write().await.decay.replace(decay);

        Ok(client)
    }
}


struct TyphoonClientMutable {
    termination_channel: Sender<()>,
    control_channel: Receiver<u32>,
    decay_channel: Sender<u32>,
    prev_packet_number: Option<u32>,
    prev_next_in: u32,
    prev_sent: u32,
    rttvar: Option<f32>,
    srtt: Option<f32>,
    decay: Option<JoinHandle<DynResult<()>>>
}

impl TyphoonClientMutable {
    fn rtt(&self) -> u32 {
        self.srtt.unwrap_or(*TYPHOON_DEFAULT_RTT).clamp(*TYPHOON_MIN_RTT, *TYPHOON_MAX_RTT) as u32
    }

    fn timeout(&self) -> u32 {
        if let (Some(srtt_val), Some(rttvar_val)) = (self.srtt, self.rttvar) {
            (srtt_val + *TYPHOON_RTT_MULT * rttvar_val as f32) as u32
        } else {
            *TYPHOON_DEFAULT_TIMEOUT as u32
        }.clamp(*TYPHOON_MIN_TIMEOUT, *TYPHOON_MAX_TIMEOUT)
    }

    fn regenerate_next_in(&mut self) {
        self.prev_next_in = generate_next_in(1.0);
        self.prev_sent = get_timestamp();
    }

    async fn send_hdsk<'a>(&mut self, symmetric: &mut Symmetric, socket: &UdpSocket, packet_number: u32, data: Option<ByteBuffer<'a>>) -> DynResult<()> {
        debug!("Sending handshake message...");
        self.regenerate_next_in();
        let packet = if let Some(package) = data {
            build_client_hdsk_data(symmetric, packet_number, self.prev_next_in, package).await?
        } else {
            build_client_hdsk(symmetric, packet_number, self.prev_next_in).await?
        };
        socket.send(&packet.slice()).await?;
        Ok(())
    }

    async fn update_timeout(&mut self) {
        let rtt = ((u32::MAX + get_timestamp() - self.prev_sent - self.prev_next_in) % u32::MAX) as f32;
        if let (Some(srtt_val), Some(rttvar_val)) = (self.srtt, self.rttvar) {
            self.srtt = Some((1.0 - *TYPHOON_ALPHA) * srtt_val + *TYPHOON_ALPHA * rtt);
            self.rttvar = Some((1.0 - *TYPHOON_BETA) * rttvar_val + *TYPHOON_BETA * (srtt_val - rtt).abs());
        } else {
            self.srtt = Some(rtt);
            self.rttvar = Some(rtt / 2.0);
        }
    }
}


struct TyphoonClientImmutable {
    socket: UdpSocket,
    references: AtomicUsize,
    internal: RwLock<TyphoonClientMutable>
}


pub struct TyphoonClient {
    keeper: bool,
    internal: Arc<TyphoonClientImmutable>,
    symmetric: Symmetric
}

macro_rules! with_write {
    ($retrieval:expr, $handle:ident, $code:block) => {{
        let mut $handle = $retrieval.internal.internal.write().await;
        let result = $code;
        drop($handle);
        result
    }};
}

macro_rules! with_read {
    ($retrieval:expr, $handle:ident, $code:block) => {{
        let $handle = $retrieval.internal.internal.read().await;
        let result = $code;
        drop($handle);
        result
    }};
}

impl TyphoonClient {
    async fn wait(&mut self, duration: Duration, decay_chan: &mut Receiver<u32>, term_chan: &mut Receiver<()>) -> Result<Option<u32>, ()> {
        let timeout = sleep(duration);
        pin!(timeout);
        select! {
            res = decay_chan.recv() => match res {
                Some(val) => Ok(Some(val)),
                None => Err(()),
            },
            _ = timeout => Ok(None),
            _ = term_chan.recv() => Err(())
        }
    }

    async fn decay_inner(&mut self, initial_next_in: u32, ctrl_chan_w: &mut Sender<u32>, decay_chan: &mut Receiver<u32>, term_chan: &mut Receiver<()>) -> DynResult<Option<u32>> {
        let next_in_timeout = with_read!(self, new_self, {
            let next_in_timeout = max(initial_next_in - new_self.rtt(), 0);
            debug!("Decay started, sleeping for {next_in_timeout} milliseconds...");
            next_in_timeout as u64
        });
        match self.wait(Duration::from_millis(next_in_timeout), decay_chan, term_chan).await {
            Ok(Some(res)) => return Ok(Some(res)),
            Ok(None) => debug!("Next in timeout expired, proceeding to decay..."),
            Err(_) => return Ok(None)
        }

        for i in 0..*TYPHOON_MAX_RETRIES {
            let shadowride_timeout = with_write!(self, new_self, {
                let packet_number = get_timestamp();
                new_self.prev_packet_number = Some(packet_number);
                debug!("Trying handshake shadowride attempt {i}...");
                if let Err(err) = ctrl_chan_w.try_send(packet_number) {
                    bail!("Control channel writing error: {err}");
                }
                (new_self.rtt() * 2) as u64
            });
            match self.wait(Duration::from_millis(shadowride_timeout), decay_chan, term_chan).await {
                Ok(Some(res)) => return Ok(Some(res)),
                Ok(None) => debug!("Shadowride timeout expired, proceeding to force sending..."),
                Err(_) => return Ok(None)
            }

            let next_in_timeout = with_write!(self, new_self, {
                match new_self.control_channel.try_recv() {
                    Ok(packet_number) => new_self.send_hdsk(&mut self.symmetric, &self.internal.socket, packet_number, None).await?,
                    Err(_) => debug!("Shadowriding handshake was already performed!"),
                }
                let next_in_timeout = new_self.prev_next_in + new_self.timeout();
                debug!("Handshake sent, waiting for response for {next_in_timeout} milliseconds...");
                next_in_timeout as u64
            });
            match self.wait(Duration::from_millis(next_in_timeout), decay_chan, term_chan).await {
                Ok(Some(res)) => return Ok(Some(res)),
                Ok(None) => debug!("Next in timeout expired, proceeding to new iteration of decay..."),
                Err(_) => return Ok(None)
            }
        }

        bail!("Decay connection timed out!")
    }

    async fn decay_cycle(&mut self, initial_next_in: u32, mut ctrl_chan_w: Sender<u32>, mut decay_chan: Receiver<u32>, mut term_chan: Receiver<()>) -> DynResult<()> {
        let mut next_in = initial_next_in;
        loop {
            match self.decay_inner(next_in, &mut ctrl_chan_w, &mut decay_chan, &mut term_chan).await {
                Ok(Some(nin)) => next_in = nin,
                Ok(None) => return Ok(()),
                Err(err) => bail!("Client decay cycle terminated error: {err}!")
            }
        }
    }
}

impl Clone for TyphoonClient {
    fn clone(&self) -> Self {
        self.internal.references.fetch_add(1, Ordering::SeqCst);
        Self { keeper: self.keeper, internal: self.internal.clone(), symmetric: self.symmetric.clone() }
    }
}

impl Reader for TyphoonClient {
    async fn read_bytes(&mut self) -> DynResult<ByteBuffer> {
        debug!("Reading started (at {}, from {})...", self.internal.socket.local_addr()?, self.internal.socket.peer_addr()?);
        loop {
            let buffer = get_buffer(None).await;
            with_read!(self, new_self, {
                if let Some(th) = &new_self.decay {
                    if th.is_finished() {
                        bail!("Decay thread finished!");
                    }
                }
            });
            let size = match self.internal.socket.recv(&mut buffer.slice_mut()).await {
                Ok(res) => {
                    debug!("Received a packet of size: {res}");
                    res
                },
                Err(err) => {
                    warn!("Invalid packet read error: {err}");
                    continue;
                }
            };
            debug!("Peer packet read: {} bytes", buffer.len());
            let message_parse_result = with_read!(self, new_self, {
                parse_server_message(&mut self.symmetric, buffer.rebuffer_end(size), new_self.prev_packet_number).await
            });
            let (msgtp, cons, data) = match message_parse_result {
                Ok((msgtp, cons, data)) => {
                    if msgtp as u8 & ProtocolFlag::HDSK as u8 == 1 {
                        with_write!(self, new_self, {
                            new_self.prev_packet_number = None;
                            new_self.update_timeout().await;
                        });
                    }
                    (msgtp, cons, data)
                },
                Err(err) => {
                    warn!("Peer packet parsing error: {err}");
                    continue;
                }
            };
            if msgtp == ProtocolMessageType::Termination {
                bail!("Connection terminated by peer!")
            }
            if let Some((_, next_in)) = cons {
                debug!("Interrupting decay with ({next_in})...");
                with_read!(self, new_self, {
                    if let Err(err) = new_self.decay_channel.try_send(next_in) {
                        warn!("Error interrupting decay: {err}");
                    }
                })
            }
            if let Some(message) = data {
                return Ok(message)
            }
        }
    }
}

impl Writer for TyphoonClient {
    async fn write_bytes(&mut self, bytes: ByteBuffer<'_>) -> DynResult<usize> {
        with_read!(self, new_self, {
            if let Some(th) = &new_self.decay {
                if th.is_finished() {
                    bail!("Decay thread finished!");
                }
            }
        });
        with_write!(self, new_self, {
            match new_self.control_channel.try_recv() {
                Ok(res) => {
                    new_self.send_hdsk(&mut self.symmetric, &self.internal.socket, res, Some(bytes)).await?;
                    Ok(0)
                },
                Err(_) => {
                    debug!("Sending data message: {} bytes...", bytes.len());
                    let packet = build_any_data(&mut self.symmetric, bytes).await?;
                    self.internal.socket.send(&packet.slice()).await?;
                    Ok(packet.len())
                }
            }
        })
    }
}

impl Drop for TyphoonClient {
    #[allow(unused_must_use)]
    fn drop(&mut self) {
        run_coroutine_sync!(async {
            if !self.keeper {
                return;
            } else if self.internal.references.load(Ordering::SeqCst) > 0 {
                self.internal.references.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            with_write!(self, new_self, {
                let decay = replace(&mut new_self.decay, None);
                if let Some(thread) = decay {
                    new_self.termination_channel.send(()).await.inspect_err(|e| warn!("Couldn't terminate decay: {e}"));
                    let result = thread.await.expect("Thread termination error!");
                    result.inspect_err(|r| info!("Inner TYPHOON thread terminated with: {r}"));
                }
            });
            debug!("Preparing termination packet to caerulean...");
            let packet = build_any_term(&mut self.symmetric).await.expect("Couldn't build termination packet!");
            debug!("Termination packet of size {} sending...", packet.len());
            self.internal.socket.send(&packet.slice()).await.inspect_err(|e| warn!("Couldn't send termination packet: {e}"));
        });
    }
}
