use std::cmp::max;
use std::future::Future;
use std::mem::replace;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::u32;

use async_dropper::AsyncDrop;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use rand::Rng;
use simple_error::bail;
use tokio::net::UdpSocket;
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::select;
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;
use tonic::async_trait;

use crate::bytes::{get_buffer, ByteBuffer};
use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::common::{ProtocolFlag, ProtocolMessageType};
use crate::rng::get_rng;
use crate::{DynResult, ReaderWriter};
use super::typhoon_core::*;
use super::ProtocolClientHandle;


lazy_static! {
    static ref LocalTokioRuntime: Runtime = Builder::new_current_thread().enable_all().build().expect("Failed to start TYPHOON runtime!");
}

fn run_coroutine<'a, F: Future<Output = R> + 'a, R: 'a>(future: F) -> R {
    let handle = match Handle::try_current() {
        Ok(res) => res,
        Err(_) => LocalTokioRuntime.handle().clone(),
    };
    handle.block_on(future)
}


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
            let buffer = get_buffer(None);
            match socket.recv(&mut buffer.slice_mut()).await {
                Ok(res) => debug!("Received initialization packet of size: {res}"),
                Err(err) => {
                    warn!("Invalid packet read error: {err}");
                    continue;
                }
            };
            let (user_id, next_in) = match parse_server_init(cipher, buffer, packet_number) {
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
            let (mut symmetric, packet) = build_client_init(&self.asymmetric, packet_number, next_in, &self.token)?;
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

    async fn connect(&mut self) -> DynResult<impl ReaderWriter> {
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

        let (ctrl_sender, ctrl_receiver) = mpsc::channel(1);
        let (decay_sender, decay_receiver) = mpsc::channel(1);
        let (termination_sender, termination_receiver) = mpsc::channel(1);
        let client = TyphoonClient {
            internal: Arc::new(RwLock::new(TyphoonClientInternal {
                socket,
                termination_channel: termination_sender,
                control_channel: ctrl_receiver,
                decay_channel: decay_sender,
                prev_packet_number: None,
                prev_next_in: 0,
                prev_sent: 0,
                rttvar: None,
                srtt: None,
                decay: None
            })),
            symmetric: cipher
        };

        let mut client_clone = client.clone();
        let decay = spawn(move || {
            run_coroutine(client_clone.decay_cycle(next_in, ctrl_sender, decay_receiver, termination_receiver))
        });
        client.internal.write().await.decay.replace(decay);

        Ok(client)
    }
}

impl <'a> ProtocolClientHandle<'a> for TyphoonHandle<'a> {
    #[allow(refining_impl_trait)]
    fn new(key: ByteBuffer<'_>, token: ByteBuffer<'a>, address: Ipv4Addr, port: u16, local: Option<Ipv4Addr>) -> DynResult<Self> {
        debug!("Creating TYPHOON protocol handle...");
        let peer_address = SocketAddr::new(IpAddr::V4(address), port);
        let local_address = match local {
            Some(ip) => SocketAddr::new(IpAddr::V4(ip), 0),
            None => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        debug!("Handle set up to connect {local_address} (local) to {peer_address} (caerulean)!");
        Ok(TyphoonHandle {
            peer_address: peer_address,
            asymmetric: Asymmetric::new(&key)?,
            local: local_address,
            token
        })
    }

    fn connect(&mut self) -> DynResult<impl ReaderWriter> {
        run_coroutine(self.connect())
    }
}


struct TyphoonClientInternal {
    socket: UdpSocket,
    termination_channel: mpsc::Sender<()>,
    control_channel: mpsc::Receiver<u32>,
    decay_channel: mpsc::Sender<u32>,
    prev_packet_number: Option<u32>,
    prev_next_in: u32,
    prev_sent: u32,
    rttvar: Option<f32>,
    srtt: Option<f32>,
    decay: Option<JoinHandle<DynResult<()>>>
}

impl TyphoonClientInternal {
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

    async fn send_hdsk<'a>(&mut self, symmetric: &mut Symmetric, packet_number: u32, data: Option<ByteBuffer<'a>>) -> DynResult<()> {
        debug!("Sending handshake message...");
        self.regenerate_next_in();
        let packet = if let Some(package) = data {
            build_client_hdsk_data(symmetric, packet_number, self.prev_next_in, package)?
        } else {
            build_client_hdsk(symmetric, packet_number, self.prev_next_in)?
        };
        self.socket.send(&packet.slice()).await?;
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

#[async_trait]
impl AsyncDrop for TyphoonClientInternal {
    #[allow(unused_must_use)]
    async fn async_drop(&mut self) {
        self.termination_channel.send(()).await.expect("Decay cycle terminator is None!");
        let decay = replace(&mut self.decay, None).and_then(|t| Some(t.join()));
        if let Some(thread) = decay {
            let result = thread.expect("Thread termination error!");
            result.inspect_err(|r| info!("Inner TYPHOON thread terminated with: {r}"));
        }
    }
}


pub struct TyphoonClient {
    internal: Arc<RwLock<TyphoonClientInternal>>,
    symmetric: Symmetric
}

macro_rules! with_write {
    ($retrieval:expr, $handle:ident, $code:block) => {{
        let mut $handle = $retrieval.internal.write().await;
        let result = $code;
        drop($handle);
        result
    }};
}

macro_rules! with_read {
    ($retrieval:expr, $handle:ident, $code:block) => {{
        let $handle = $retrieval.internal.read().await;
        let result = $code;
        drop($handle);
        result
    }};
}

impl TyphoonClient {
    async fn sleep(&mut self, duration: Duration, decay_chan: &mut mpsc::Receiver<u32>, termination_chan: &mut mpsc::Receiver<()>) -> DynResult<Option<u32>> {
        select! {
            _ = termination_chan.recv() => bail!("Thread terminated!"),
            res = decay_chan.recv() => match res {
                Some(val) => Ok(Some(val)),
                None => bail!("Decay channel was closed!"),
            },
            _ = tokio::time::sleep(duration) => Ok(None)
        }
    }

    async fn decay_inner(&mut self, initial_next_in: u32, ctrl_chan_w: &mut mpsc::Sender<u32>, decay_chan: &mut mpsc::Receiver<u32>, termination_chan: &mut mpsc::Receiver<()>) -> DynResult<u32> {
        let next_in_timeout = with_read!(self, new_self, {
            let next_in_timeout = max(initial_next_in - new_self.rtt(), 0);
            debug!("Decay started, sleeping for {next_in_timeout} milliseconds...");
            next_in_timeout as u64
        });
        match self.sleep(Duration::from_millis(next_in_timeout), decay_chan, termination_chan).await {
            Ok(Some(res)) => return Ok(res),
            Ok(None) => debug!("Next in timeout expired, proceeding to decay..."),
            Err(err) => bail!(err)
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
            match self.sleep(Duration::from_millis(shadowride_timeout), decay_chan, termination_chan).await {
                Ok(Some(res)) => return Ok(res),
                Ok(None) => debug!("Shadowride timeout expired, proceeding to force sending..."),
                Err(err) => bail!(err)
            }

            let next_in_timeout = with_write!(self, new_self, {
                match new_self.control_channel.try_recv() {
                    Ok(packet_number) => new_self.send_hdsk(&mut self.symmetric, packet_number, None).await?,
                    Err(_) => debug!("Shadowriding handshake was already performed!"),
                }
                let next_in_timeout = new_self.prev_next_in + new_self.timeout();
                debug!("Handshake sent, waiting for response for {next_in_timeout} milliseconds...");
                next_in_timeout as u64
            });
            match self.sleep(Duration::from_millis(next_in_timeout), decay_chan, termination_chan).await {
                Ok(Some(res)) => return Ok(res),
                Ok(None) => debug!("Next in timeout expired, proceeding to new iteration of decay..."),
                Err(err) => bail!(err)
            }
        }

        bail!("Decay connection timed out!")
    }

    async fn decay_cycle(&mut self, initial_next_in: u32, mut ctrl_chan_w: mpsc::Sender<u32>, mut decay_chan: mpsc::Receiver<u32>, mut termination_chan: mpsc::Receiver<()>) -> DynResult<()> {
        let mut next_in = initial_next_in;
        loop {
            match self.decay_inner(next_in, &mut ctrl_chan_w, &mut decay_chan, &mut termination_chan).await {
                Ok(nin) => next_in = nin,
                Err(err) => bail!("Client decay cycle terminated error: {err}!")
            }
        }
    }

    async fn read_bytes(&mut self) -> DynResult<ByteBuffer> {
        let reader = self.internal.read().await;
        debug!("Reading started (at {}, from {})...", reader.socket.local_addr()?, reader.socket.peer_addr()?);
        loop {
            let buffer = get_buffer(None);
            with_read!(self, new_self, {
                if let Some(th) = &new_self.decay {
                    if th.is_finished() {
                        bail!("Decay thread finished!");
                    }
                }
            });
            if let Err(err) = reader.socket.recv(&mut buffer.slice_mut()).await {
                warn!("Invalid packet read error: {err}");
                continue;
            }
            debug!("Peer packet read: {} bytes", buffer.len());
            let (msgtp, cons, data) = match parse_server_message(&mut self.symmetric, buffer, reader.prev_packet_number) {
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

    async fn write_bytes(&mut self, bytes: ByteBuffer<'_>) -> DynResult<usize> {
        with_read!(self, new_self, {
            if let Some(th) = &new_self.decay {
                if th.is_finished() {
                    bail!("Decay thread finished!");
                }
            }
        });
        with_write!(self, new_self, {
            match new_self.control_channel.recv().await {
                Some(packet_number) => new_self.send_hdsk(&mut self.symmetric, packet_number, Some(bytes)).await?,
                None => {
                    debug!("Sending data message: {} bytes...", bytes.len());
                    let packet = build_any_data(&mut self.symmetric, bytes)?;
                    new_self.socket.send(&packet.slice()).await?;
                    return Ok(packet.len())
                }
            }
        });
        Ok(0)
    }
}

impl Clone for TyphoonClient {
    fn clone(&self) -> Self {
        Self { internal: self.internal.clone(), symmetric: self.symmetric.clone() }
    }
}

impl ReaderWriter for TyphoonClient {
    fn read_bytes(&mut self) -> DynResult<ByteBuffer> {
        run_coroutine(self.read_bytes())
    }

    fn write_bytes(&mut self, bytes: ByteBuffer) -> DynResult<usize> {
        run_coroutine(self.write_bytes(bytes))
    }
}

#[async_trait]
impl AsyncDrop for TyphoonClient {
    #[allow(unused_must_use)]
    async fn async_drop(&mut self) {
        let new_int = self.internal.read().await;
        let packet = build_any_term(&mut self.symmetric).expect("Couldn't build termination packet!");
        run_coroutine(new_int.socket.send(&packet.slice())).expect("Couldn't send termination packet: {e}");
    }
}
