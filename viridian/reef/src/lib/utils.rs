use std::any::type_name;
use std::env::var;
use std::str::FromStr;


pub fn parse_env<T: FromStr>(key: &str, default: Option<T>) -> T {
    match var(key) {
        Ok(res) => match res.parse::<T>() {
            Ok(res) => res,
            Err(_) => panic!("'{key}' should be conversable to {}!", type_name::<T>()),
        },
        Err(_) => match default {
            Some(res) => res,
            None => panic!("'{key}' should be set!"),
        },
    }
}

pub fn parse_str_env(key: &str, default: Option<&str>) -> String {
    match var(key) {
        Ok(res) => res,
        Err(_) => match default {
            Some(res) => res.to_string(),
            None => panic!("'{key}' should be set!"),
        },
    }
}
