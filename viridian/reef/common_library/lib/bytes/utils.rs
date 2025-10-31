pub fn preserve_vector(vector: Vec<u8>) -> *mut u8 {
    vector.leak().as_mut_ptr()
}

pub fn allocate_ptr(size: usize) -> *mut u8 {
    preserve_vector(vec![0u8; size])
}

pub fn free_ptr(ptr: *mut u8, length: usize) {
    let vector = unsafe { Vec::<u8>::from_raw_parts(ptr, length, length) };
    drop(vector);
}
