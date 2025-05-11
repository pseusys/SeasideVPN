use std::cmp::max;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::u32;

use async_dropper::AsyncDrop;
use futures::channel::mpsc;
use futures::StreamExt;
use log::{debug, error, info, warn};
use rand::Rng;
use simple_error::bail;
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::sync::{oneshot, RwLock};
use tokio::time::timeout;
use tonic::async_trait;

use crate::crypto::{Asymmetric, Symmetric};
use crate::protocol::common::{ProtocolFlag, ProtocolMessageType};
use crate::utils::get_packet;
use crate::DynResult;
use super::typhoon_core::*;
use super::{ProtocolClient, ProtocolClientHandle};


fn get_timestamp() -> u32 {
    let time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
    (time % u32::MAX as u128) as u32
}

fn generate_next_in(multiplier: f32) -> u32 {
    (OsRng.gen_range(*TYPHOON_MIN_NEXT_IN..=*TYPHOON_MAX_NEXT_IN) as f32 * multiplier) as u32
}


pub struct TyphoonHandle {
    peer_address: SocketAddr,
    asymmetric: Asymmetric,
    local: SocketAddr,
    token: Vec<u8>
}

impl TyphoonHandle {
    pub async fn new(key: &Vec<u8>, token: &Vec<u8>, address: Ipv4Addr, port: u16, local: Option<Ipv4Addr>) -> DynResult<TyphoonHandle> {
        let peer_address = format!("{address}:{port}").parse()?;
        let local_address = match local {
            Some(ip) => format!("{ip}:0"),
            None => "0.0.0.0:0".to_string(),
        }.parse()?;
        let asymmetric_key = match key.clone().try_into() {
            Ok(res) => res,
            Err(_) => bail!("Error converting key to Asymmetric key!"),
        };
        Ok(TyphoonHandle {
            peer_address,
            asymmetric: Asymmetric::new(&asymmetric_key)?,
            local: local_address,
            token: token.clone()
        })
    }

    async fn read_server_init(&self, stream: &mut UdpSocket, cipher: &Symmetric, packet_number: u32) -> DynResult<(u16, u32)> {
        let mut buffer = get_packet();
        loop {
            match stream.recv(buffer.as_mut_slice()).await {
                Ok(_) => match parse_server_init(cipher, buffer.as_mut_slice(), packet_number) {
                    Ok(res) => return Ok(res),
                    Err(err) => warn!("Peer packet parsing error: {err}")
                },
                Err(err) => warn!("Invalid packet read error: {err}")
            }
        }
    }

    pub async fn connect_inner(&mut self, stream: &mut UdpSocket) -> DynResult<(u16, u32, Symmetric)> {
        let mut packet_number: u32;
        for i in 0..*TYPHOON_MAX_RETRIES {
            packet_number = get_timestamp();
            let next_in = generate_next_in(*TYPHOON_INITIAL_NEXT_IN);
            let (key, packet) = build_client_init(&self.asymmetric, packet_number, next_in, &self.token)?;
            let symmetric_key = match key.try_into() {
                Ok(res) => res,
                Err(_) => bail!("Error converting key to Symmetric key!"),
            };
            let symmetric = Symmetric::new(&symmetric_key);
            stream.send(&packet).await?;
            let sleep = next_in + (*TYPHOON_DEFAULT_TIMEOUT).clamp(*TYPHOON_MIN_TIMEOUT, *TYPHOON_MAX_TIMEOUT);
            match timeout(Duration::from_millis(sleep as u64), self.read_server_init(stream, &symmetric, packet_number)).await {
                Ok(Ok((user_id, next_in))) => return Ok((user_id, next_in, symmetric)),
                Ok(Err(err)) => warn!("Error while parsing server response: {err}"),
                Err(_) => info!("Peer packet waiting timeout, retrying...")
            }
        }
        bail!("Connection could not be established (maximum retries reached)!")
    }
}

#[async_trait]
impl ProtocolClientHandle for TyphoonHandle {
    async fn connect(&mut self) -> DynResult<Arc<dyn ProtocolClient>> {
        debug!("Binding connection client to {}...", self.local);
        let mut socket = UdpSocket::bind(self.local).await?;

        debug!("Connecting to listener at {}", self.peer_address);
        socket.connect(self.peer_address).await?;
        debug!("Current user address: {}", socket.local_addr()?);

        let (user_id, next_in, cipher) = self.connect_inner(&mut socket).await?;
        info!("Discovered server at {}", socket.peer_addr()?);

        let mut main_address = self.peer_address.clone();
        main_address.set_port(user_id);
        socket.connect(main_address).await?;
        info!("Connected to the server at {}", socket.peer_addr()?);

        let (ctxw, ctxr) = oneshot::channel();
        let (errw, errr) = mpsc::channel(1);
        let (ctrlw, ctrlr) = mpsc::channel(1);
        let (decayw, decayr) = mpsc::channel(1);
        let client = Arc::new(RwLock::new(TyphoonClient {
            stream: socket,
            symmetric: cipher,
            control_channel: ctrlr,
            decay_channel: decayw,
            error_channel: errr,
            terminator: Some(ctxw),
            prev_packet_number: None,
            prev_next_in: 0,
            prev_sent: 0,
            rttvar: None,
            srtt: None
        }));
        spawn(client.clone().decay_cycle(next_in, ctrlw, decayr, errw, ctxr));

        Ok(client)
    }
}


trait TyphoonClientInner {
    async fn decay_inner(&self, initial_next_in: u32, ctrl_chan_w: &mut mpsc::Sender<u32>, decay_chan: &mut mpsc::Receiver<u32>) -> DynResult<u32>;
    async fn decay_cycle(self: Arc<Self>, initial_next_in: u32, ctrl_chan_w: mpsc::Sender<u32>, decay_chan: mpsc::Receiver<u32>, err_chan: mpsc::Sender<String>, term_chan: oneshot::Receiver<()>);
}

pub struct TyphoonClient {
    stream: UdpSocket,
    symmetric: Symmetric,
    control_channel: mpsc::Receiver<u32>,
    decay_channel: mpsc::Sender<u32>,
    error_channel: mpsc::Receiver<String>,
    terminator: Option<oneshot::Sender<()>>,
    prev_packet_number: Option<u32>,
    prev_next_in: u32,
    prev_sent: u32,
    rttvar: Option<f32>,
    srtt: Option<f32>
}

macro_rules! with_write {
    ($retrieval:expr, $handle:ident, $code:block) => {{
        let mut $handle = $retrieval.write().await;
        let result = $code;
        drop($handle);
        result
    }};
}

macro_rules! with_read {
    ($retrieval:expr, $handle:ident, $code:block) => {{
        let $handle = $retrieval.read().await;
        let result = $code;
        drop($handle);
        result
    }};
}

impl TyphoonClient {
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

    async fn send_hdsk(&mut self, packet_number: u32, data: Option<&Vec<u8>>) -> DynResult<()> {
        debug!("Sending handshake message...");
        self.regenerate_next_in();
        let packet = if let Some(package) = data {
            build_client_hdsk_data(&self.symmetric, packet_number, self.prev_next_in, package)?
        } else {
            build_client_hdsk(&self.symmetric, packet_number, self.prev_next_in)?
        };
        self.stream.send(packet.as_slice()).await?;
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

impl TyphoonClientInner for RwLock<TyphoonClient> {
    async fn decay_inner(&self, initial_next_in: u32, ctrl_chan_w: &mut mpsc::Sender<u32>, decay_chan: &mut mpsc::Receiver<u32>) -> DynResult<u32> {
        let next_in_timeout = with_read!(self, new_self, {
            let next_in_timeout = max(initial_next_in - new_self.rtt(), 0);
            debug!("Decay started, sleeping for {next_in_timeout} milliseconds...");
            next_in_timeout as u64
        });
        match timeout(Duration::from_millis(next_in_timeout), decay_chan.next()).await {
            Ok(Some(next_in)) => return Ok(next_in),
            Ok(None) => bail!("Decay channel was closed!"),
            Err(_) => debug!("Next in timeout expired, proceeding to decay..."),
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
            match timeout(Duration::from_millis(shadowride_timeout), decay_chan.next()).await {
                Ok(Some(next_in)) => return Ok(next_in),
                Ok(None) => bail!("Decay channel was closed!"),
                Err(_) => debug!("Shadowride timeout expired, proceeding to force sending..."),
            }

            let next_in_timeout = with_write!(self, new_self, {
                match new_self.control_channel.try_next() {
                    Ok(Some(packet_number)) => new_self.send_hdsk(packet_number, None).await?,
                    Ok(None) => bail!("Control channel was closed!"),
                    Err(_) => debug!("Shadowriding handshake was already performed!"),
                }
                let next_in_timeout = new_self.prev_next_in + new_self.timeout();
                debug!("Handshake sent, waiting for response for {next_in_timeout} milliseconds...");
                next_in_timeout as u64
            });
            match timeout(Duration::from_millis(next_in_timeout), decay_chan.next()).await {
                Ok(Some(next_in)) => return Ok(next_in),
                Ok(None) => bail!("Decay channel was closed!"),
                Err(_) => debug!("Next in timeout expired, proceeding to new iteration of decay..."),
            }
        }

        bail!("Decay connection timed out!")
    }

    async fn decay_cycle(self: Arc<Self>, initial_next_in: u32, mut ctrl_chan_w: mpsc::Sender<u32>, mut decay_chan: mpsc::Receiver<u32>, mut err_chan: mpsc::Sender<String>, mut term_chan: oneshot::Receiver<()>) {
        let mut next_in = initial_next_in;
        loop {
            match self.decay_inner(next_in, &mut ctrl_chan_w, &mut decay_chan).await {
                Ok(nin) => next_in = nin,
                Err(err) => {
                    if let Ok(_) = term_chan.try_recv() {
                        info!("Client decay cycle cleaned up!");
                        return;
                    }
                    warn!("Client decay cycle terminated error: {err}!");
                    if let Err(err) = err_chan.try_send(err.to_string()) {
                        error!("Client decay cycle terminated on unreported error: {err}!");
                        return;
                    }
                    return;
                }
            }
        }
    }
}

#[async_trait]
impl ProtocolClient for RwLock<TyphoonClient> {
    async fn read_bytes(&self) -> DynResult<Vec<u8>> {
        let reader = self.read().await;
        let mut buffer = get_packet();

        debug!("Reading started (at {}, from {})...", reader.stream.local_addr()?, reader.stream.peer_addr()?);
        loop {
            with_write!(self, new_self, {
                match new_self.error_channel.try_next() {
                    Ok(Some(err)) => bail!("Inner error received: {err}"),
                    Ok(None) => bail!("Inner error channel was closed!"),
                    Err(_) => debug!("No inner error received, proceeding..")
                }
            });
            if let Err(err) = reader.stream.recv(&mut buffer).await {
                warn!("Invalid packet read error: {err}");
                continue;
            }
            debug!("Peer packet read: {} bytes", buffer.len());
            let (msgtp, cons, data) = match parse_server_message(&reader.symmetric, &mut buffer, reader.prev_packet_number) {
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
                let mut writer = self.write().await;
                debug!("Interrupting decay with ({next_in})...");
                if let Err(err) = writer.decay_channel.try_send(next_in) {
                    warn!("Error interrupting decay: {err}");
                }
            }
            if let Some(message) = data {
                return Ok(message)
            }
        }
    }

    async fn write_bytes(&self, bytes: &Vec<u8>) -> DynResult<usize> {
        let mut writer = self.write().await;
        match writer.error_channel.try_next() {
            Ok(Some(err)) => bail!("Inner error received: {err}"),
            Ok(None) => bail!("Inner error channel was closed!"),
            Err(_) => debug!("No inner error received, proceeding..")
        }
        match writer.control_channel.try_next() {
            Ok(Some(packet_number)) => writer.send_hdsk(packet_number, Some(bytes)).await?,
            Ok(None) => bail!("Control channel was closed!"),
            Err(_) => {
                debug!("Sending data message...");
                let packet = build_any_data(&writer.symmetric, bytes)?;
                writer.stream.send(&packet).await?;
                return Ok(packet.len())
            }
        }
        Ok(0)
    }
}

#[async_trait]
impl AsyncDrop for TyphoonClient {
    #[allow(unused_must_use)]
    async fn async_drop(&mut self) {
        self.terminator.take().and_then(|t| Some(t.send(()))).expect("Decay cycle terminator is None!").expect("Couldn't terminate decay cycle!");
        let packet = build_any_term(&self.symmetric).expect("Couldn't build termination packet!");
        self.stream.send(&packet).await.inspect_err(|e| warn!("Couldn't send termination packet: {e}"));
    }
}
