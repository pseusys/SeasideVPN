use tokio::test;

use super::{bytes_to_string};


#[test]
async fn test_bytes_to_string() {
    let c_string = vec![72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33, 0];
    let conv = bytes_to_string(&c_string).expect("Error converting array to string!");
    assert_eq!(conv, "Hello, World!", "C-style string doesn't match expected!");
}

// async fn test_send_netlink_message() {}
