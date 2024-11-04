# Reef

## Take care: DNS

If you use any DNS manager (as `resolvectl` on Linux), it is quite common that the only DNS servers you have configured are your local network DNS.
Obviously, when using VPN, they might be unavailable from the outside internet.
If you have received the warning stating that your DNS servers are misconfigured during VPN startup, search how to add some publicly available DNS as fallback option.
Solid choices usually are `8.8.8.8`, `8.8.4.4` (Google DNS), `1.1.1.1` (Cloudflare DNS), etc.
