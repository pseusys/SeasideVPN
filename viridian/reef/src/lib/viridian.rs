use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::Arc;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::generic_array::typenum::U32;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::XChaCha20Poly1305;
use tokio::spawn;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::tunnel::Tunnel;


const CIPHER_NONCE_SIZE: usize = 24;


pub struct Viridian {
    pub socket: Arc<UdpSocket>,
    pub tunnel: Arc<Tunnel>,
    address: Ipv4Addr,

    send_handle: Option<JoinHandle<Result<(), ()>>>,
    receive_handle: Option<JoinHandle<Result<(), ()>>>
}


impl Viridian {
    pub fn new(socket: UdpSocket, tunnel: Tunnel, address: Ipv4Addr) -> Viridian {
        Viridian {
            socket: Arc::new(socket),
            tunnel: Arc::new(tunnel),
            address,
            send_handle: None,
            receive_handle: None
        }
    }

    async fn send_to_caerulean(self: &Viridian, cipher: XChaCha20Poly1305, user_id: u16) -> impl Future<Output = Result<(), ()>> {
        let socket = Arc::clone(&self.socket);
        let tunnel = Arc::clone(&self.tunnel);
        let address = (self.address, user_id);
        async move {
            let mut buffer = vec![0; usize::from(u16::MAX)];
            loop {
                let length = match tunnel.read_bytes(&mut buffer).await {
                    Err(res) => panic!("Error reading from tunnel: {res}!"),
                    Ok(res) => res
                };
                println!("PING: Bytes to encrypt: {:?}!", &buffer[..length]);
                let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                let ciphertext = match cipher.encrypt(&nonce, &buffer[..length]) {
                    Err(res) => panic!("Error encrypting packet: {res}!"),
                    Ok(res) => res
                };
                let result = [&nonce[..], &ciphertext[..]].concat();
                match socket.send_to(&result, address).await {
                    Err(res) => panic!("Error writing to socket: {res}!"),
                    Ok(res) => println!("Sent {res} bytes to caerulean: {result:?}!")
                };
            }
        }
    }
    
    async fn receive_from_caerulean(self: &Viridian, cipher: XChaCha20Poly1305) -> impl Future<Output = Result<(), ()>> {
        let socket = Arc::clone(&self.socket);
        let tunnel = Arc::clone(&self.tunnel);
        async move {
            let mut buffer = vec![0; usize::from(u16::MAX)];
            loop {
                let length = match socket.recv(&mut buffer).await {
                    Err(res) => panic!("Error reading from socket: {res}!"),
                    Ok(res) => res
                };
                let nonce = GenericArray::from_slice(&buffer[..CIPHER_NONCE_SIZE]);
                let plaintext = match cipher.decrypt(nonce, &buffer[CIPHER_NONCE_SIZE..length]) {
                    Err(res) => panic!("Error decrypting packet: {res}!"),
                    Ok(res) => res
                };
                match tunnel.write_bytes(&plaintext).await {
                    Err(res) => panic!("Error writing to tunnel: {res}!"),
                    Ok(res) => println!("Sent {res} bytes to tunnel!")
                };
            }
        }
    }

    pub async fn open(&mut self, key: GenericArray<u8, U32>, user_id: u16) {
        let cipher = XChaCha20Poly1305::new(&key);
        self.send_handle = Some(spawn(self.send_to_caerulean(cipher.clone(), user_id).await));
        self.receive_handle = Some(spawn(self.receive_from_caerulean(cipher.clone()).await));
    }

    pub fn close(&mut self) {
        if let Some(recv_hand) = self.receive_handle.as_mut() {
            recv_hand.abort();
        }
        if let Some(send_hand) = self.send_handle.as_mut() {
            send_hand.abort();
        }
    }
}

impl Drop for Viridian {
    fn drop(&mut self) -> () {
        self.close()
    }
}
