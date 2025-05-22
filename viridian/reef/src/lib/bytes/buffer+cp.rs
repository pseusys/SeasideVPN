use std::{ptr::copy_nonoverlapping, slice::from_raw_parts_mut, sync::Arc};

use chacha20poly1305::aead::{Buffer, Error, Result};

use super::{pool::BytePool, utils::free_ptr, utils::allocate_ptr, utils::preserve_vector};


pub struct ByteBuffer<'a> {
    data: Arc<*mut u8>,
    length: usize,
    start: usize,
    end: usize,
    pool: Option<&'a BytePool>
}

impl<'a> ByteBuffer<'a> {
    #[inline]
    fn precise(before_cap: usize, size: usize, after_cap: usize, pool: &'a BytePool) -> Self {
        let buffer_end = before_cap + size;
        ByteBuffer {
            data: Arc::new(pool.pull()),
            length: buffer_end + after_cap,
            start: before_cap,
            end: buffer_end,
            pool: Some(pool)
        }
    }

    #[inline]
    pub fn empty(size: usize) -> Self {
        ByteBuffer {
            data: Arc::new(allocate_ptr(size)),
            length: size,
            start: 0,
            end: size,
            pool: None
        }
    }

    #[inline]
    pub fn slice(&self) -> &[u8] {
        unsafe { from_raw_parts_mut(self.data.add(self.start), self.end - self.start) }
    }

    #[inline]
    pub fn slice_mut(&mut self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(self.data.add(self.start), self.end - self.start) }
    }

    #[inline]
    pub fn slice_start(&self, start: usize) -> &[u8] {
        let new_start = self.start + start;
        assert!(new_start <= self.end, "ByteBuffer has negative length!");
        unsafe { from_raw_parts_mut(self.data.add(new_start), self.end - new_start) }
    }

    #[inline]
    pub fn slice_start_mut(&mut self, start: usize) -> &mut [u8] {
        let new_start = self.start + start;
        assert!(new_start <= self.end, "ByteBuffer has negative length!");
        unsafe { from_raw_parts_mut(self.data.add(new_start), self.end - new_start) }
    }

    #[inline]
    pub fn slice_end(&self, end: usize) -> &[u8] {
        let new_end = self.start + end;
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        unsafe { from_raw_parts_mut(self.data.add(self.start), new_end - self.start) }
    }

    #[inline]
    pub fn slice_end_mut(&mut self, end: usize) -> &mut [u8] {
        let new_end = self.start + end;
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        unsafe { from_raw_parts_mut(self.data.add(self.start), new_end - self.start) }
    }

    #[inline]
    pub fn slice_both(&self, start: usize, end: usize) -> &[u8] {
        let new_start = self.start + start;
        let new_end = self.start + end;
        assert!(new_start <= new_end, "ByteBuffer has negative length!");
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        unsafe { from_raw_parts_mut(self.data.add(new_start), new_end - new_start) }
    }

    #[inline]
    pub fn slice_both_mut(&mut self, start: usize, end: usize) -> &mut [u8] {
        let new_start = self.start + start;
        let new_end = self.start + end;
        assert!(new_start <= new_end, "ByteBuffer has negative length!");
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        unsafe { from_raw_parts_mut(self.data.add(new_start), new_end - new_start) }
    }

    #[inline]
    pub fn split(&self, divide: usize) -> (&[u8], &[u8]) {
        let new_divide = self.start + divide;
        assert!(new_divide <= self.end, "ByteBuffer has negative length!");
        (
            unsafe { from_raw_parts_mut(self.data.add(self.start), divide) },
            unsafe { from_raw_parts_mut(self.data.add(new_divide), self.end - new_divide) }
        )
    }

    #[inline]
    pub fn split_mut(&mut self, divide: usize) -> (&mut [u8], &mut [u8]) {
        let new_divide = self.start + divide;
        assert!(new_divide <= self.end, "ByteBuffer has negative length!");
        (
            unsafe { from_raw_parts_mut(self.data.add(self.start), divide) },
            unsafe { from_raw_parts_mut(self.data.add(new_divide), self.end - new_divide) }
        )
    }

    pub fn split_buf(&self, divide: usize) -> (Self, Self) {
        let new_divide = self.start + divide;
        assert!(new_divide <= self.end, "ByteBuffer has negative length!");
        (
            ByteBuffer {
                data: self.data.clone(),
                length: self.length,
                start: self.start,
                end: new_divide,
                pool: self.pool
            },
            ByteBuffer {
                data: self.data.clone(),
                length: self.length,
                start: new_divide,
                end: self.end,
                pool: self.pool
            }
        )
    }

    pub fn append(&mut self, other: &[u8]) -> Self {
        let other_length = other.len();
        let new_end = self.end + other_length;
        assert!(new_end <= self.length, "ByteBuffer forward capacity insufficient!");
        unsafe { copy_nonoverlapping(other.as_ptr(), self.data.add(self.start + self.end), other_length) }
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: self.start,
            end: new_end,
            pool: self.pool
        }
    }

    pub fn append_buf(&mut self, other: &ByteBuffer) -> Self {
        self.append(other.slice())
    }

    pub fn prepend(&mut self, other: &[u8]) -> Self {
        let other_length = other.len();
        assert!(self.start >= self.length, "ByteBuffer backward capacity insufficient!");
        unsafe { copy_nonoverlapping(other.as_ptr(), self.data.add(self.start - other_length), other_length) }
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: self.start - other_length,
            end: self.end,
            pool: self.pool
        }
    }

    pub fn prepend_buf(&mut self, other: &ByteBuffer) -> Self {
        self.prepend(other.slice())
    }

    #[inline]
    pub fn rebuffer_start(&self, start: usize) -> Self {
        let new_start = self.start + start;
        assert!(new_start <= self.end, "ByteBuffer has negative length!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: new_start,
            end: self.end,
            pool: self.pool
        }
    }

    #[inline]
    pub fn rebuffer_end(&self, end: usize) -> Self {
        let new_end = self.start + end;
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: self.start,
            end: new_end,
            pool: self.pool
        }
    }

    #[inline]
    pub fn rebuffer_both(&self, start: usize, end: usize) -> Self {
        let new_start = self.start + start;
        let new_end = self.start + end;
        assert!(new_start <= new_end, "ByteBuffer has negative length!");
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: new_start,
            end: new_end,
            pool: self.pool
        }
    }
}

unsafe impl<'a> Send for ByteBuffer<'a> {}

impl<'a> AsMut<[u8]> for ByteBuffer<'a> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.slice_mut()
    }
}

impl<'a> AsRef<[u8]> for ByteBuffer<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.slice()
    }
}

impl<'a> Buffer for ByteBuffer<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.length
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[inline]
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        let other_length = other.len();
        let new_end = self.end + other_length;
        if new_end <= self.length {
            unsafe { copy_nonoverlapping(other.as_ptr(), self.data.add(self.start + self.end), other_length) }
            self.end = new_end;
            Ok(())
        } else {
            Err(Error {})
        }
    }

    #[inline]
    fn truncate(&mut self, len: usize) {
        self.end = self.start + len
    }
}

impl<'a> From<Vec<u8>> for ByteBuffer<'a> {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        let length = value.len();
        ByteBuffer {
            data: Arc::new(preserve_vector(value)),
            length: length,
            start: 0,
            end: length,
            pool: None
        }
    }
}

impl<'a> From<&[u8]> for ByteBuffer<'a> {
    #[inline]
    fn from(value: &[u8]) -> Self {
        let vector = value.to_vec();
        let length = vector.len();
        ByteBuffer {
            data: Arc::new(preserve_vector(vector)),
            length: length,
            start: 0,
            end: length,
            pool: None
        }
    }
}

impl<'a> Into<Vec<u8>> for ByteBuffer<'a> {
    #[inline]
    fn into(self) -> Vec<u8> {
        self.slice().to_vec()
    }
}

impl<'a> Clone for ByteBuffer<'a> {
    #[inline]
    fn clone(&self) -> Self {
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: self.start,
            end: self.end,
            pool: self.pool
        }
    }
}

impl<'a> Drop for ByteBuffer<'a> {
    fn drop(&mut self) {
        if Arc::strong_count(&self.data) == 1 {
            if let Some(pl) = self.pool {
                pl.push(*self.data)
            } else {
                free_ptr(*self.data, self.length);
            }
        }
    }
}
