use std::cell::{Ref, RefCell, RefMut};
use std::rc::Rc;
use std::slice::from_raw_parts_mut;

use chacha20poly1305::aead::{Buffer, Error, Result};

use super::pool::KeptVector;


pub struct ByteBuffer<'a> {
    data: Rc<RefCell<KeptVector<'a>>>,
    length: usize,
    start: usize,
    end: usize
}

impl<'a> ByteBuffer<'a> {
    #[inline] // TOOD: private
    pub fn precise(before_cap: usize, size: usize, after_cap: usize, kept: KeptVector<'a>) -> Self {
        let buffer_end = before_cap + size;
        ByteBuffer {
            data: Rc::new(RefCell::new(kept)),
            length: buffer_end + after_cap,
            start: before_cap,
            end: buffer_end
        }
    }

    #[inline]
    pub fn empty(size: usize) -> Self {
        ByteBuffer {
            data: Rc::new(RefCell::new(KeptVector::new(size))),
            length: size,
            start: 0,
            end: size
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.start
    }
}


impl<'a> ByteBuffer<'a> {
    #[inline]
    pub fn get(&self, at: usize) -> Ref<u8> {
        Ref::map(self.data.borrow(), |b| &b[at])
    }

    #[inline]
    pub fn set(&self, at: usize, value: u8) {
        let mut byte_ref = RefMut::map(self.data.borrow_mut(), |b| &mut b[at]);
        *byte_ref = value;
    }

    #[inline]
    pub fn slice(&self) -> Ref<[u8]> {
        Ref::map(self.data.borrow(), |b| &b[self.start..self.end])
    }

    #[inline]
    pub fn slice_mut(&self) -> RefMut<[u8]> {
        RefMut::map(self.data.borrow_mut(), |b| &mut b[self.start..self.end])
    }

    #[inline]
    pub fn slice_start(&self, start: usize) -> Ref<[u8]> {
        Ref::map(self.data.borrow(), |b| &b[self.start + start..self.end])
    }

    #[inline]
    pub fn slice_start_mut(&self, start: usize) -> RefMut<[u8]> {
        RefMut::map(self.data.borrow_mut(), |b| &mut b[self.start + start..self.end])
    }

    #[inline]
    pub fn slice_end(&self, end: usize) -> Ref<[u8]> {
        Ref::map(self.data.borrow(), |b| &b[self.start..self.start + end])
    }

    #[inline]
    pub fn slice_end_mut(&self, end: usize) -> RefMut<[u8]> {
        RefMut::map(self.data.borrow_mut(), |b| &mut b[self.start..self.start + end])
    }

    #[inline]
    pub fn slice_both(&self, start: usize, end: usize) -> Ref<[u8]> {
        Ref::map(self.data.borrow(), |b| &b[self.start + start..self.start + end])
    }

    #[inline]
    pub fn slice_both_mut(&self, start: usize, end: usize) -> RefMut<[u8]> {
        RefMut::map(self.data.borrow_mut(), |b| &mut b[self.start + start..self.start + end])
    }

    #[inline]
    pub fn split(&self, divide: usize) -> (Ref<[u8]>, Ref<[u8]>) {
        let new_divide = self.start + divide;
        (
            Ref::map(self.data.borrow(), |b| &b[self.start..new_divide]),
            Ref::map(self.data.borrow(), |b| &b[new_divide..self.end])
        )
    }
}

impl<'a> ByteBuffer<'a> {
    pub fn rebuffer_start(&self, start: usize) -> Self {
        let new_start = self.start + start;
        assert!(new_start <= self.end, "ByteBuffer has negative length!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: new_start,
            end: self.end
        }
    }

    pub fn rebuffer_end(&self, end: usize) -> Self {
        let new_end = self.start + end;
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: self.start,
            end: new_end
        }
    }

    pub fn rebuffer_both(&self, start: usize, end: usize) -> Self {
        let new_start = self.start + start;
        let new_end = self.start + end;
        assert!(new_start <= new_end, "ByteBuffer has negative length!");
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: new_start,
            end: new_end
        }
    }

    pub fn expand_start(&self, size: usize) -> Self {
        let new_start = self.start - size;
        assert!(size >= self.start, "ByteBuffer has negative length!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: new_start,
            end: self.end
        }
    }

    pub fn expand_end(&self, size: usize) -> Self {
        let new_end = self.end + size;
        assert!(new_end <= self.length, "ByteBuffer exceeded its backward capacity!");
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: self.start,
            end: new_end
        }
    }

    pub fn split_buf(&self, divide: usize) -> (Self, Self) {
        let new_divide = self.start + divide;
        assert!(new_divide <= self.end, "ByteBuffer has negative length!");
        (
            ByteBuffer {
                data: self.data.clone(),
                length: self.length,
                start: self.start,
                end: new_divide
            },
            ByteBuffer {
                data: self.data.clone(),
                length: self.length,
                start: new_divide,
                end: self.end
            }
        )
    }

    pub fn append(&self, other: &[u8]) -> Self {
        let other_length = other.len();
        let new_end = self.end + other_length;
        assert!(new_end <= self.length, "ByteBuffer forward capacity insufficient!");
        self.data.borrow_mut()[self.end..new_end].copy_from_slice(other);
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: self.start,
            end: new_end
        }
    }

    pub fn append_buf(&self, other: &ByteBuffer) -> Self {
        self.append(&other.slice())
    }

    pub fn prepend(&self, other: &[u8]) -> Self {
        let other_length = other.len();
        let new_start = self.start - other_length;
        assert!(other_length <= self.start, "ByteBuffer backward capacity insufficient!");
        self.data.borrow_mut()[new_start..self.start].copy_from_slice(other);
        ByteBuffer {
            data: self.data.clone(),
            length: self.length,
            start: new_start,
            end: self.end
        }
    }

    pub fn prepend_buf(&self, other: &ByteBuffer) -> Self {
        self.prepend(&other.slice())
    }
}

impl<'a> AsMut<[u8]> for ByteBuffer<'a> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        let pointer = self.slice_mut().as_ptr() as *mut u8;
        unsafe { from_raw_parts_mut(pointer, self.len()) }
    }
}

impl<'a> AsRef<[u8]> for ByteBuffer<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        let pointer = self.slice_mut().as_ptr() as *mut u8;
        unsafe { from_raw_parts_mut(pointer, self.len()) }
    }
}

impl<'a> Buffer for ByteBuffer<'a> {
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.start == self.end
    }

    #[inline]
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<()> {
        let other_length = other.len();
        let new_end = self.end + other_length;
        if new_end <= self.length {
            self.data.borrow_mut()[self.end..new_end].copy_from_slice(other);
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
    fn from(value: Vec<u8>) -> Self {
        let length = value.len();
        ByteBuffer {
            data: Rc::new(RefCell::new(KeptVector::from(value))),
            length: length,
            start: 0,
            end: length
        }
    }
}

impl<'a> From<&[u8]> for ByteBuffer<'a> {
    fn from(value: &[u8]) -> Self {
        let vector = value.to_vec();
        let length = vector.len();
        ByteBuffer {
            data: Rc::new(RefCell::new(KeptVector::from(vector))),
            length: length,
            start: 0,
            end: length
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
            end: self.end
        }
    }
}
