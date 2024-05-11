use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use dns_lookup::lookup_host;
use rand::prelude::{thread_rng, RngCore, Rng};
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use generated::whirlpool_viridian_client::WhirlpoolViridianClient;
use generated::{WhirlpoolAuthenticationRequest, WhirlpoolAuthenticationResponse, ControlHandshakeRequest, ControlHandshakeResponse, ControlHealthcheck, ControlException, ControlExceptionStatus};

use super::tunnel::{new_tunnel, Tunnel};
use super::viridian::Viridian;
use super::super::VERSION;

mod generated {
    tonic::include_proto!("generated");
}

const GRPC_PROTOCOL: &str = "https";
const MAX_TAIL_LENGTH: usize = 64;
const SYMM_KEY_LENGTH: usize = 32;


pub struct Coordinator {
    tunnel: Box<dyn Tunnel>,
    viridian: Option<Viridian>,
    socket: UdpSocket,
    client: WhirlpoolViridianClient<Channel>,

    address: String,
    node_payload: String,
    user_name: String,
    min_hc_time: u16,
    max_hc_time: u16,

    session_token: Option<Vec<u8>>,
    session_key: Option<Vec<u8>>
}


fn parse_address(address: &str) -> Option<Ipv4Addr> {
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(pip)) => Some(pip),
        _ => match lookup_host(address) {
            Ok(rip) => match rip.first() {
                Some(IpAddr::V4(rsip)) => Some(*rsip),
                _ => None
            },
            Err(_) => None
        }
    }
}

impl Coordinator {
    pub async fn new(payload: &str, address: &str, ctrl_port: u16, user_name: &str, min_hc_time: u16, max_hc_time: u16, max_timeout: f32, tunnel_name: &str) -> Result<Coordinator, Box<dyn Error>> {
        let viridian_host = format!("{GRPC_PROTOCOL}://{address}:{ctrl_port}");
        let resolved_ip  = match parse_address(address) {
            Some(ip) => ip,
            None => return Err(Box::from(format!("Address {address} can't be resolved!")))
        };

        let tunnel = new_tunnel(tunnel_name, resolved_ip).await?;
        let socket = UdpSocket::bind((tunnel.default_interface().0, 0)).await?;

        let caerulean_max_timeout = Duration::from_secs_f32(max_timeout);
        let endpoint = Endpoint::from_shared(viridian_host.clone()).ok().unwrap().timeout(caerulean_max_timeout).connect_timeout(caerulean_max_timeout);
        let client = WhirlpoolViridianClient::connect(endpoint).await?;

        if min_hc_time < 1 {
            return Err(Box::from("Minimum healthcheck time shouldn't be less than 1 second!"));
        }
        if max_hc_time < 1 {
            return Err(Box::from("Maximum healthcheck time shouldn't be less than 1 second!"));
        }

        Ok(Coordinator {
            tunnel,
            viridian: None,
            socket,
            client,
            address: viridian_host,
            node_payload: payload.to_string(),
            user_name: user_name.to_string(),
            min_hc_time,
            max_hc_time,
            session_token: None,
            session_key: None
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
            println!("log error status: {res}");
            return Err(Box::from("Token receiving failed"));
        }

        let initialize_control_res = self.initialize_control().await;
        if let Err(ref res) = initialize_control_res {
            println!("log error status: {res}");
            return Err(Box::from("Control initialization failed"));
        }

        if let Some(viridian) = &self.viridian {
            viridian.open();
        }
        Ok(initialize_control_res.unwrap())
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        let mut user_id = self.initialize_connection().await?;
        loop {
            let control = self.perform_control(user_id).await;
            if let Err(ctrl) = control {
                println!("log error status: {ctrl}");
                user_id = self.initialize_connection().await?;
            }
        }
    }

    fn make_grpc_request<T>(&self, message: T) -> Request<T> {
        let mut randomizer = thread_rng();
        let mut tail = Vec::with_capacity(randomizer.gen_range(1..MAX_TAIL_LENGTH));
        randomizer.fill_bytes(&mut tail);

        let mut request = Request::new(message);
        request.metadata_mut().append_bin("tail", MetadataValue::from_bytes(&tail));
        request
    }

    async fn receive_token(&mut self) -> Result<(), tonic::Status> {
        let mut session_key = Vec::with_capacity(SYMM_KEY_LENGTH);
        thread_rng().fill_bytes(&mut session_key);

        let message = WhirlpoolAuthenticationRequest {uid: self.user_name.clone(), session: session_key.clone(), payload: self.node_payload.clone()};
        let response = self.client.authenticate(self.make_grpc_request(message)).await;

        match response {
            Ok(resp) => {
                self.session_key = Some(resp.get_ref().token.clone());
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
        let response = self.client.handshake(self.make_grpc_request(message)).await;

        self.viridian = Some(Viridian::new());
        match response {
            Ok(resp) => Ok(resp.get_ref().user_id as u16),
            Err(resp) => Err(resp)
        }
    }

    async fn perform_control(&mut self, user_id: u16) -> Result<tonic::Response<()>, tonic::Status> {
        let next_in = thread_rng().gen_range(self.min_hc_time..self.max_hc_time);
        let message = ControlHealthcheck {user_id: i32::from(user_id), next_in: i32::from(next_in)};
        let response = self.client.healthcheck(self.make_grpc_request(message)).await;
        sleep(Duration::from_secs(u64::from(next_in))).await;
        response
    }

    pub async fn interrupt(&mut self, user_id: u16, exception: Option<String>) -> Result<(), Box<dyn Error>> {
        let message = ControlException {
            status: i32::from(ControlExceptionStatus::Termination),
            user_id: i32::from(user_id),
            message: exception
        };
        let response = self.client.exception(self.make_grpc_request(message)).await;

        Ok(())
    }
}

impl Drop for Coordinator {
    fn drop(&mut self) -> () {
        if let Some(ref viridian) = self.viridian {
            if viridian.is_operational() {
                viridian.close()
            }
        }
    }
}
