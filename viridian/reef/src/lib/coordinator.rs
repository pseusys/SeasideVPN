use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::fs::read_to_string;

use rand::prelude::{thread_rng, RngCore, Rng};
use rand::rngs::ThreadRng;
use tokio::net::UdpSocket;
use tokio::runtime::Handle;
use tokio::task::block_in_place;
use tokio::time::sleep;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::Request;

use generated::whirlpool_viridian_client::WhirlpoolViridianClient;
use generated::{WhirlpoolAuthenticationRequest, WhirlpoolAuthenticationResponse, ControlHandshakeRequest, ControlHandshakeResponse, ControlHealthcheck, ControlException, ControlExceptionStatus};

use super::tunnel::Tunnel;
use super::viridian::Viridian;
use super::VERSION;

mod generated {
    tonic::include_proto!("generated");
}

const GRPC_PROTOCOL: &str = "https";
const MAX_TAIL_LENGTH: usize = 64;
const SYMM_KEY_LENGTH: usize = 32;
const NONE_USER_ID: u16 = 0;


pub struct Coordinator {
    tunnel: Tunnel,
    viridian: Option<Viridian>,
    socket: UdpSocket,
    client: WhirlpoolViridianClient<Channel>,

    node_payload: String,
    user_name: String,
    user_id: u16,
    min_hc_time: u16,
    max_hc_time: u16,

    session_token: Option<Vec<u8>>,
    session_key: Option<Vec<u8>>,
    randomizer: ThreadRng
}


impl Coordinator {
    pub async fn new(address: Ipv4Addr, ctrl_port: u16, payload: &str, user_name: &str, min_hc_time: u16, max_hc_time: u16, max_timeout: f32, tunnel_name: &str, ca: Option<&str>) -> Result<Coordinator, Box<dyn Error>> {
        let viridian_host = format!("{GRPC_PROTOCOL}://{address}:{ctrl_port}");

        if min_hc_time < 1 {
            return Err(Box::from("Minimum healthcheck time shouldn't be less than 1 second!"));
        }
        if max_hc_time < 1 {
            return Err(Box::from("Maximum healthcheck time shouldn't be less than 1 second!"));
        }

        let tunnel = Tunnel::new(tunnel_name, address).await?;
        let socket = UdpSocket::bind((tunnel.default_interface().0, 0)).await?;

        let tls = match ca {
            Some(certificate) => ClientTlsConfig::new().ca_certificate(Certificate::from_pem(read_to_string(certificate)?.as_bytes())),
            None => ClientTlsConfig::new().with_webpki_roots()
        };
        let caerulean_max_timeout = Duration::from_secs_f32(max_timeout);
        let channel = Channel::from_shared(viridian_host)?.timeout(caerulean_max_timeout).connect_timeout(caerulean_max_timeout).tls_config(tls)?.connect().await?;
        let client = WhirlpoolViridianClient::new(channel);

        Ok(Coordinator {
            tunnel,
            viridian: None,
            socket,
            client,
            node_payload: payload.to_string(),
            user_name: user_name.to_string(),
            user_id: NONE_USER_ID,
            min_hc_time,
            max_hc_time,
            session_token: None,
            session_key: None,
            randomizer: thread_rng()
        })
    }

    async fn initialize_connection(&mut self) -> Result<u16, Box<dyn Error>> {
        if let Some(viridian) = &self.viridian {
            if viridian.is_operational() {
                viridian.close();
            }
        }

        let recevive_token_res = self.receive_token().await;
        if let Err(res) = recevive_token_res {
            println!("log receive token error status: {res}");
            return Err(Box::from("Token receiving failed"));
        }

        let initialize_control_res = self.initialize_control().await;
        if let Err(ref res) = initialize_control_res {
            println!("log initialize control error status: {res}");
            return Err(Box::from("Control initialization failed"));
        }

        if let Some(viridian) = &self.viridian {
            viridian.open();
        }
        Ok(initialize_control_res.unwrap())
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        self.user_id = self.initialize_connection().await?;
        loop {
            let control = self.perform_control(self.user_id).await;
            if let Err(ctrl) = control {
                println!("log error status: {ctrl}");
                self.user_id = self.initialize_connection().await?;
            }
        }
    }

    fn make_grpc_request<T>(&mut self, message: T) -> Request<T> {
        let mut tail = Vec::with_capacity(self.randomizer.gen_range(1..MAX_TAIL_LENGTH));
        self.randomizer.fill_bytes(&mut tail);

        let mut request = Request::new(message);
        request.metadata_mut().append_bin("seaside-tail-bin", MetadataValue::from_bytes(&tail));
        request
    }

    async fn receive_token(&mut self) -> Result<(), tonic::Status> {
        let mut session_key = vec![0; SYMM_KEY_LENGTH];
        self.randomizer.fill_bytes(&mut session_key);

        let message = WhirlpoolAuthenticationRequest {uid: self.user_name.clone(), session: session_key.clone(), payload: self.node_payload.clone()};
        let request = self.make_grpc_request(message);
        let response = self.client.authenticate(request).await;

        match response {
            Ok(resp) => {
                self.session_key = Some(session_key);
                self.session_token = Some(resp.get_ref().token.clone());
                Ok(())
            },
            Err(resp) => Err(resp)
        }
    }

    async fn initialize_control(&mut self) -> Result<u16, tonic::Status> {
        let message = ControlHandshakeRequest {
            token: self.session_token.clone().unwrap(),
            version: VERSION.to_string(),
            payload: Some(self.node_payload.clone()),
            address: self.tunnel.default_interface().0.octets().to_vec(),
            port: i32::from(self.socket.local_addr().ok().unwrap().port())
        };
        let request = self.make_grpc_request(message);
        let response = self.client.handshake(request).await;

        self.viridian = Some(Viridian::new());
        match response {
            Ok(resp) => Ok(resp.get_ref().user_id as u16),
            Err(resp) => Err(resp)
        }
    }

    async fn perform_control(&mut self, user_id: u16) -> Result<tonic::Response<()>, tonic::Status> {
        let next_in = self.randomizer.gen_range(self.min_hc_time..self.max_hc_time);
        let message = ControlHealthcheck {user_id: i32::from(user_id), next_in: i32::from(next_in)};
        let request = self.make_grpc_request(message);
        let response = self.client.healthcheck(request).await;
        sleep(Duration::from_secs(u64::from(next_in))).await;
        response
    }

    async fn interrupt(&mut self, exception: Option<String>) -> Result<(), Box<dyn Error>> {
        let message = ControlException {
            status: i32::from(ControlExceptionStatus::Termination),
            user_id: i32::from(self.user_id),
            message: exception
        };
        let request = self.make_grpc_request(message);
        let response = self.client.exception(request).await;
        match response {
            Ok(_) => Ok(()),
            Err(resp) => Err(Box::from(resp))
        }
    }
}

impl Drop for Coordinator {
    fn drop(&mut self) -> () {
        if self.user_id != NONE_USER_ID {
            block_in_place(move || {
                Handle::current().block_on(async move {
                    // TODO: log message!
                    self.interrupt(None).await.expect("...");
                });
            });
        }
    }
}
