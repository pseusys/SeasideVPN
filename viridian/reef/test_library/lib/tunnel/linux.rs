use std::error::Error;
use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::str::FromStr;

use regex::Regex;
use simple_error::bail;


pub fn run_command<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(cmd: &str, args: I) -> Result<(String, String), Box<dyn Error + Sync + Send>> {
    let cmd = match Command::new(cmd).args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(res) => res,
        Err(res) => bail!(res),
    };
    let res = match cmd.wait_with_output() {
        Ok(res) => res,
        Err(res) => bail!(res),
    };
    if res.status.success() {
        Ok((String::from_utf8_lossy(&res.stdout).to_string(), String::from_utf8_lossy(&res.stderr).to_string()))
    } else {
        bail!(String::from_utf8_lossy(&res.stderr).to_string())
    }
}

pub fn parse_route_info_from_output(route_output: &str) -> Result<(Option<String>, Option<String>, Option<Ipv4Addr>), Box<dyn Error + Sync + Send>> {
    let destination_regex = Regex::new(r"^(?<destination>\S+)")?;
    let destination_match = destination_regex.captures(route_output);
    let destination_res = destination_match.and_then(|m| Some((&m["destination"]).to_string()));

    let device_regex = Regex::new(r"dev (?<device>\S+)")?;
    let device_match = device_regex.captures(route_output);
    let device_res = device_match.and_then(|m| Some((&m["device"]).to_string()));

    let gateway_regex = Regex::new(r"via (?<gateway>\d+\.\d+\.\d+\.\d+)")?;
    let gateway_match = gateway_regex.captures(route_output);
    let gateway_res = gateway_match.and_then(|m| Ipv4Addr::from_str(&m["gateway"]).ok());

    Ok((destination_res, device_res, gateway_res))
}
