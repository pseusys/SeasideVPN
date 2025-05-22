use std::borrow::Cow;
use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::engine::Engine;
use simple_error::{bail, require_with};
use url::Url;

use crate::bytes::ByteBuffer;
use crate::DynResult;


pub fn parse_client_link<'a>(link: String) -> DynResult<(String, ByteBuffer<'a>, Option<u16>, Option<u16>, ByteBuffer<'a>)> {
    let url = Url::parse(&link)?;
    if url.scheme() != "seaside+client" {
        bail!("Unexpected link scheme: {}", url.scheme());
    }

    let address = require_with!(url.host_str(), "Address string was not found!");
    let query = url.query_pairs().collect::<HashMap<Cow<str>, Cow<str>>>();

    let raw_public = require_with!(query.get("public"), "Public key query not found!").as_bytes();
    let parsed_public = ByteBuffer::from(URL_SAFE_NO_PAD.decode(&raw_public)?);

    let raw_token = require_with!(query.get("token"), "Viridian token query not found!").as_bytes();
    let parsed_token = ByteBuffer::from(URL_SAFE_NO_PAD.decode(&raw_token)?);

    let port = match query.get("port") {
        Some(res) => Some(res.parse()?),
        None => None,
    };
    let typhoon = match query.get("typhoon") {
        Some(res) => Some(res.parse()?),
        None => None,
    };

    Ok((address.to_string(), parsed_public, port, typhoon, parsed_token))
}
