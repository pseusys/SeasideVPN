use std::mem::take;
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

use super::buffer::ByteBuffer;


pub struct KeptVector<'a> {
    data: Vec<u8>,
    pool: Option<&'a BytePool>
}

impl KeptVector<'_> {
    pub fn new(size: usize) -> Self {
        KeptVector {
            data: vec![0u8; size],
            pool: None
        }
    }
}

impl<'a> From<Vec<u8>> for KeptVector<'a> {
    fn from(value: Vec<u8>) -> Self {
        KeptVector {
            data: value,
            pool: None
        }
    }
}

impl Deref for KeptVector<'_> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for KeptVector<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<'a> Drop for KeptVector<'a> {
    fn drop(&mut self) {
        if let Some(pl) = self.pool {
            pl.push(take(&mut self.data))
        }
    }
}


pub struct BytePool {
    before_cap: usize,
    size: usize,
    after_cap: usize,
    capacity: usize,
    pool: Mutex<Vec<Vec<u8>>>
}

impl <'a>BytePool {
    pub fn new(before_cap: usize, size: usize, after_cap: usize, initial: usize) -> Self {
        let capacity = before_cap + size + after_cap;
        BytePool {
            before_cap,
            size,
            after_cap,
            capacity,
            pool: Mutex::new(vec![vec![0u8; capacity]; initial])
        }
    }

    fn push(&self, ptr: Vec<u8>) {
        self.pool.lock().expect("Byte pool panicked!").push(ptr);
    }

    fn pull(&'a self) -> KeptVector<'a> {
        KeptVector {
            data: match self.pool.lock().expect("Byte pool panicked!").pop() {
                Some(res) => res,
                None => vec![0u8; self.capacity],
            },
            pool: Some(self)
        }
    }

    pub fn allocate(&'a self, size: usize) -> ByteBuffer<'a> {
        let remaining_after_cap = self.size + self.after_cap - size;
        assert!(size >= self.size, "Requested size greater than initial size!");
        ByteBuffer::precise(self.before_cap, size, remaining_after_cap, self.pull())
    }
}
