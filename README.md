# Cryptalias

![Cryptalias Logo](logo.png)

A modern, privacy-focused alias system for cryptocurrency addresses.

## Overview

Cryptalias provides human-readable aliases (e.g., `alice$example.com`) for cryptocurrency addresses, building upon OpenAlias with enhanced security and privacy features:

- **Dynamic address generation**: Request fresh addresses from wallet services to prevent address reuse
- **Cryptographic signatures**: All responses are signed for client verification
- **Per-client address stability**: Same client receives consistent addresses within a configurable TTL window
- **Extensible architecture**: Support for database-backed aliases and third-party integrations

This project is a reference implementation of the Cryptalias protocol. Other
implementations can (and should) be built in different languages while remaining
compatible with the protocol.

## Why Cryptalias?

OpenAlias offers familiar and human-friendly crypto aliases but was designed for static address mappings. Cryptalias maintains the same user-friendly `name@domain` format (using `$` instead of `@` to avoid protocol confusion) while addressing privacy concerns:

**OpenAlias approach:**

- Fixed address mappings in DNS

**Cryptalias approach:**

- Static or dynamic address resolution
- Per-client stability windows to reduce address sniffing
- Cryptographically signed responses
- Clear integration path for external wallet services

For implementation details, see [PROTOCOL.md](PROTOCOL.md).

## Client libraries

Minimal HTTP client helpers are available in `clients/` (JavaScript, TypeScript, Rust, Dart, C++, Swift, Kotlin). The Go resolver lives in `internal/cryptalias/resolve.go`.
Each client verifies signatures and enforces `expires`.

## Built-in resolver

The `cryptalias` binary can act as a one-shot resolver without starting the server:

```bash
cryptalias resolve "alice$example.com" xmr
```

Add `--json` for structured output:

```bash
cryptalias resolve --json "alice$example.com" xmr
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- A domain with DNS access
- A Monero wallet (for the example configuration)

### Installation

1. **Create a config file:**

   ```bash
   mkdir -p cryptalias
   cd cryptalias
   ```

2. **Prepare your wallet:**

   Place wallet files in `./monero/wallet/` and configure in
   `config.yml`:

   ```yaml
   tokens:
     - name: Monero
       tickers: [xmr]
       endpoint:
         type: internal
         address: http://monero-wallet-rpc:18083/json_rpc
         username: your-username
         password: your-password
         wallet_file: main
         wallet_password: your-wallet-password
   ```

   **Note:** Monero requires `/json_rpc` endpoint suffix and uses HTTP Digest authentication.

3. **Create a docker-compose file (uses the GHCR image):**

   ```yaml
   services:
     monero-wallet-rpc:
       image: sethsimmons/simple-monero-wallet-rpc:latest
       user: 1000:1000
       volumes:
         - ./monero:/home/monero/
       command:
         - --confirm-external-bind
         - --rpc-bind-ip=0.0.0.0
         - --rpc-bind-port=18083
         - --rpc-login=${MONERO_RPC_USER:-cryptalias}:${MONERO_RPC_PASS:-change-me}
         - --wallet-dir=/home/monero/wallet
         - --daemon-address=${MONERO_DAEMON_ADDRESS:-monerod:18081}

     cryptalias:
       image: ghcr.io/kaigoh/cryptalias:main
       user: 1000:1000
       volumes:
         - ./cryptalias:/config
       command: ["/config/config.yml"]
   ```

   This assumes `monerod` is reachable as `monerod:18081` from the wallet RPC
   container. Adjust `--daemon-address` to match your setup. You can also
   override defaults via environment variables:
   - `MONERO_DAEMON_ADDRESS`
   - `MONERO_RPC_USER`
   - `MONERO_RPC_PASS`

4. **Start the stack:**

   ```bash
   docker compose up --build
   ```

5. **Configure DNS:**

   Cryptalias generates cryptographic keys automatically. Copy the DNS TXT record from the logs:

   ```
   _cryptalias.yourdomain.com TXT "pubkey=..."
   ```

6. **Test resolution:**
   ```
   http://cryptalias.localhost/_cryptalias/resolve/xmr/me$cryptalias.localhost
   ```

## Configuration

### Minimal Configuration Example

```yaml
base_url: http://cryptalias.localhost
public_port: 8080

logging:
  level: info

rate_limit:
  enabled: true
  requests_per_minute: 60
  burst: 10

resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff
    header: X-Forwarded-For

verify:
  interval_minutes: 5

domains:
  - domain: cryptalias.localhost
    aliases:
      - alias: me
        wallet:
          ticker: xmr
          address: ""
          account_index: 0

tokens:
  - name: Monero
    tickers: [xmr]
    endpoint:
      type: internal
      address: http://monero-wallet-rpc:18083/json_rpc
      username: cryptalias
      password: change-me
      wallet_file: main
      wallet_password: change-me-wallet
```

The configuration file is monitored for changes and reloads automatically. Invalid configurations are rejected, preserving the last valid state.

### Client Identity Strategies

Cryptalias uses client identity for both rate limiting and address stability. Choose the strategy that matches your deployment:

| Strategy         | Use Case                       | Configuration                                   |
| ---------------- | ------------------------------ | ----------------------------------------------- |
| `remote_address` | Direct connections (no proxy)  | Uses TCP connection IP                          |
| `xff`            | Behind reverse proxy (default) | Uses `X-Forwarded-For` header                   |
| `xff_ua`         | Shared IPs (office NAT, etc.)  | Combines `X-Forwarded-For` with user agent hash |
| `header`         | Custom proxy setup             | Uses specified header                           |
| `header_ua`      | Custom proxy + shared IPs      | Combines custom header with user agent hash     |

**Reverse proxy examples:**

<details>
<summary>Traefik</summary>

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff
    header: X-Forwarded-For
```

</details>

<details>
<summary>Nginx</summary>

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff
    header: X-Forwarded-For
```

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

</details>

<details>
<summary>Caddy</summary>

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff
    header: X-Forwarded-For
```

</details>

### Static vs Dynamic Aliases

**Static alias** (returns fixed address):

```yaml
wallet:
  ticker: xmr
  address: "89abc..."
```

**Dynamic alias** (requests fresh address from wallet):

```yaml
wallet:
  ticker: xmr
  address: ""
  account_index: 0
```

### Account Management

Configure multiple aliases using different wallet accounts:

```yaml
aliases:
  - alias: personal
    wallet:
      ticker: xmr
      address: ""
      account_index: 0

  - alias: donations
    wallet:
      ticker: xmr
      address: ""
      account_index: 1
```

Optional routing parameters: `account_index`, `account_id`, `wallet_id`

### External Wallet Services

Integrate external wallet services via gRPC:

```yaml
endpoint:
  type: external
  address: wallet-service:50051
  token: "authentication-token" # Optional
```

See `proto/cryptalias/v1/wallet_service.proto` for the gRPC contract.

## Deployment

### Reverse Proxy Configuration

Cryptalias requires two routing paths:

1. **Discovery endpoint** on your domain: `/.well-known/cryptalias/`
2. **Resolution endpoint** on Cryptalias host: `/_cryptalias/`

<details>
<summary>Traefik Example</summary>

```yaml
labels:
  - traefik.enable=true

  # Discovery on resolved domain
  - traefik.http.routers.cryptalias-wellknown.rule=Host(`example.com`) && PathPrefix(`/.well-known/cryptalias/`)
  - traefik.http.routers.cryptalias-wellknown.entrypoints=websecure
  - traefik.http.routers.cryptalias-wellknown.tls.certresolver=letsencrypt
  - traefik.http.routers.cryptalias-wellknown.service=cryptalias-svc

  # Resolution on Cryptalias host
  - traefik.http.routers.cryptalias-public.rule=Host(`cryptalias.example.com`) && PathPrefix(`/_cryptalias/`)
  - traefik.http.routers.cryptalias-public.entrypoints=websecure
  - traefik.http.routers.cryptalias-public.tls.certresolver=letsencrypt
  - traefik.http.routers.cryptalias-public.service=cryptalias-svc

  - traefik.http.services.cryptalias-svc.loadbalancer.server.port=8080
```

</details>

<details>
<summary>Caddy Example</summary>

```caddyfile
example.com {
  handle_path /.well-known/cryptalias/* {
    reverse_proxy cryptalias:8080
  }
}

cryptalias.example.com {
  reverse_proxy cryptalias:8080
}
```

</details>

<details>
<summary>Nginx Example</summary>

```nginx
server {
  server_name example.com;

  location ^~ /.well-known/cryptalias/ {
    proxy_pass http://cryptalias:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}

server {
  server_name cryptalias.example.com;

  location /_cryptalias/ {
    proxy_pass http://cryptalias:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

</details>

### Domain Verification

Cryptalias performs periodic health checks on configured domains:

- Validates `/.well-known/cryptalias/configuration` endpoint
- Verifies the public key in `/.well-known/cryptalias/configuration` matches the domain key
- Checks DNS `_cryptalias` TXT record

**Domains failing verification will not resolve aliases** until health checks pass.

**Monitoring endpoints:**

- `GET /.well-known/cryptalias/status` - Domain health status
- `GET /healthz` - Service liveness check

Configure verification interval:

```yaml
verify:
  interval_minutes: 5
```

## Security Considerations

### Important Security Notes

⚠️ **Never run Cryptalias or wallet services as root.** Use dedicated, unprivileged users (UID/GID 1000+).
Cryptalias refuses to start as root.

⚠️ **Use hot wallets only.** Cryptalias should never connect to cold storage. Monitor and sweep balances regularly.

⚠️ **Keep wallet balances minimal.** Treat the wallet as disposable in case of compromise.

### Built-in Security Features

- **Rate limiting**: Prevents scraping and spam (configurable per-minute limits)
- **Address caching**: Per-client TTL reduces address enumeration
- **Cryptographic signatures**: All responses include domain key signatures for client verification

## Troubleshooting

### Common Issues

**"Unknown alias" (404 error)**

- Verify domain matches `domains[].domain` in config
- Ensure alias exists under that domain
- Confirm ticker is defined in `tokens[].tickers`
- Check alias format: `alias$domain` or `alias+tag$domain`

**Config changes not taking effect**

- Check logs for "config reload rejected"
- Validation errors preserve the previous valid configuration
- Review YAML syntax and required fields

**All requests appear to come from same client**

- Incorrect `client_identity.strategy` for your deployment
- Direct connections require `remote_address`
- Proxied deployments require `xff` with proper header forwarding

**Dynamic alias not working**

- Static mode requires non-empty `wallet.address`
- Empty `address` field triggers dynamic resolution

**YAML unmarshaling errors**

- Ensure objects are formatted as maps, not lists
- Example: `wallet:` should be a single object, not an array

**Monero wallet RPC failures**

- Verify wallet RPC can connect to daemon
- Confirm wallet files exist at configured path
- Check RPC credentials match in both compose file and config
- Ensure endpoint address ends with `/json_rpc`
- Remember Monero uses HTTP Digest authentication

**Signature verification failures**

- Confirm both `private_key` and `public_key` are set for each domain
- Copy DNS TXT record from logs if keys were auto-generated
- Verify DNS propagation of `_cryptalias` TXT record

## Development

### Project Structure

```
├── cmd/cryptalias/          # Main application entry point
├── internal/cryptalias/     # Core server implementation
├── proto/cryptalias/v1/     # gRPC protocol definitions
├── config.example.yml       # Example configuration
├── docker-compose.yml       # Docker stack definition
└── PROTOCOL.md             # Protocol specification
```

### Integration Points

- **gRPC contract**: `proto/cryptalias/v1/wallet_service.proto`
- **Server implementation**: `internal/cryptalias/server.go`
- **Application entry**: `cmd/cryptalias/main.go`

## Donate

If you find Cryptalias useful, donations are gratefully accepted to support ongoing development:

**Monero:** `8BUwkJ4LWiJS7bHAsKxBbaR1dkxzcvMJoNqGeCcLEt42betKeFnnEEA7xEJLBNNA1ngBS4V4pTVt6g8S4XZyePsc1UH5msc`

![Monero Donation QR Code](monero-donation-qrcode-small.png)

## License

See [LICENSE](LICENSE) for details.

## Roadmap

- Database-backed alias configuration
- Third-party integration APIs
- Additional cryptocurrency support
- Automated invoice system integration
