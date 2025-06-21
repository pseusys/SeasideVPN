use std::{marker::PhantomData, slice::{from_raw_parts, from_raw_parts_mut}};

use simple_error::bail;
use tokio::sync::watch::{Receiver, Sender};

use crate::DynResult;


#[derive(Clone, Copy)]
pub struct SendPtr<T> {
    ptr: T,
    len: usize,
    _marker: PhantomData<u8>
}

unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

pub type MutSendPtr = SendPtr<*mut u8>;
pub type ConstSendPtr = SendPtr<*const u8>;

impl MutSendPtr {
    pub fn new(buf: &mut [u8]) -> Self {
        let ptr = buf.as_mut_ptr();
        Self { ptr, len: buf.len(), _marker: PhantomData }
    }

    pub fn recreate(&self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl ConstSendPtr {
    pub fn new(buf: &[u8]) -> Self {
        let ptr = buf.as_ptr();
        Self { ptr, len: buf.len(), _marker: PhantomData }
    }

    pub fn recreate(&self) -> &[u8] {
        unsafe { from_raw_parts(self.ptr, self.len) }
    }
}


pub struct TunnelTransport<S, R: Copy> {
    sender: Sender<Option<S>>,
    receiver: Receiver<Option<R>>
}

pub type LocalTunnelTransport<T> = TunnelTransport<SendPtr<T>, usize>;
pub type RemoteTunnelTransport<T> = TunnelTransport<usize, SendPtr<T>>;

pub type LocalMutTunnelTransport = LocalTunnelTransport<*mut u8>;
pub type RemoteMutTunnelTransport = RemoteTunnelTransport<*mut u8>;
pub type LocalConstTunnelTransport = LocalTunnelTransport<*const u8>;
pub type RemoteConstTunnelTransport = RemoteTunnelTransport<*const u8>;

impl<S, R: Copy> TunnelTransport<S, R> {
    pub fn new(sender: Sender<Option<S>>, receiver: Receiver<Option<R>>) -> Self {
        Self {sender, receiver}
    }

    async fn send_internal(&mut self, data: Option<S>) -> DynResult<()> {
        if let Err(err) = self.sender.send(data) {
            bail!("Error sending packet to queue: {err}");
        }
        Ok(())
    }

    pub async fn send(&mut self, data: S) -> DynResult<()> {
        self.send_internal(Some(data)).await
    }

    pub async fn receive(&mut self) -> DynResult<R> {
        self.receiver.changed().await?;
        let borrowed = self.receiver.borrow();
        match *borrowed {
            Some(res) => Ok(res),
            None => bail!("Received None from tunnel send queue!")
        }
    }

    pub async fn close(&mut self) -> DynResult<()> {
        self.send_internal(None).await
    }
}
