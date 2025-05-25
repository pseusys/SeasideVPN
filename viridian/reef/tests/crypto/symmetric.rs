use rand::RngCore;
use tokio::test;

use crate::rng::get_rng;

use super::super::super::bytes::ByteBuffer;
use super::Symmetric;


const SAMPLE_DATA: &[u8] = b"Sample data for encryption";
const ADDITIONAL_DATA: &[u8] = b"Sample additional data for encryption";

const SAMPLE_ENCRYPTED_MESSAGE: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00+\xff\xfb\xf9\x89E\xad\x1b\xb8\x95\x92\xe5\xd3[mh\x8av\xc2L8\xf9\xec\xc4\xb5\xb3\xd6\x97&|\x8dVVmh}\xd3\xbe\xb6\x05i\xe5";


#[test]
async fn test_symmetric_encrypt() {
    let key = ByteBuffer::empty(32);
    get_rng().fill_bytes(&mut key.slice_mut());
    let mut symmetric = Symmetric::new(&key).expect("Error creating symmetric cypher!");

    let message_buffer = ByteBuffer::empty(64 + SAMPLE_DATA.len() + 64);
    let cropped_message_buffer = message_buffer.rebuffer_both(64, 64 + SAMPLE_DATA.len());
    cropped_message_buffer.slice_mut().copy_from_slice(SAMPLE_DATA);

    let raw_additional_data = ByteBuffer::from(ADDITIONAL_DATA);
    let encrypted_message = symmetric.encrypt(cropped_message_buffer, Some(&raw_additional_data)).expect("Error encrypting message");

    let encrypted_message_value: Vec<u8> = encrypted_message.into();
    assert_eq!(SAMPLE_ENCRYPTED_MESSAGE.to_vec(), encrypted_message_value, "Unexpected encrypted message value!");
}
