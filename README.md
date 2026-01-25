![Cryptalias logo](logo.png)

# Cryptalias

Cryptalias is a human-friendly alias system for crypto addresses.

It keeps the nice `name@domain` style from OpenAlias (though Cryptalias uses `name$domain` to avoid confusion with other protocols), but adds modern safety and privacy features:

- Dynamic addresses (not just fixed ones)
- Signed responses so clients can verify what they receive
- A clear path toward database-backed aliases and third-party integrations

## OpenAlias vs Cryptalias (Why this exists)

OpenAlias is great, but it assumes aliases map to fixed addresses. That can make address reuse and "sniffing" easier.

Cryptalias keeps the same spirit but changes the defaults:

- OpenAlias: fixed mappings
- Cryptalias: fixed _or_ dynamic

What Cryptalias adds on top:

- Dynamic resolution: the alias can request a fresh address from a wallet service
- Per-client stability window: the same client gets the same address for a short time (to reduce sniffing)
- Signed outputs: responses are signed with your domain key so clients can verify them
- Protocol details for client and wallet implementers: `PROTOCOL.md`

Future direction:

- Move alias config into a database
- Allow third-party integrations (for example: invoice systems that create aliases automatically)

## Donations

If you feel like this will be useful to you, donations will be gratefully recieved to help drive future development work.

Monero: `8BUwkJ4LWiJS7bHAsKxBbaR1dkxzcvMJoNqGeCcLEt42betKeFnnEEA7xEJLBNNA1ngBS4V4pTVt6g8S4XZyePsc1UH5msc`

![Monero Donation QR Code](monero-donation-qrcode.png | width=200)

## Quick start mental model

Your `config.yml` is the control panel. It answers three questions:

1. Where does the app run?
2. Which names (aliases) do I control?
3. How do I get wallet addresses for each coin/token?

Good news: the app watches the config file. Edit it, save it, and it reloads automatically. If the new config is invalid, it keeps the last good one.

## The DNS TXT record you should add

Each domain should publish its public key in DNS as a TXT record:

- Name: `_cryptalias.yourdomain.com`
- Value: `pubkey=...`

Cryptalias prints the exact TXT record value:

- When keys are generated
- When the application starts
- When the config reloads successfully

So you can copy the log line directly into your DNS provider.

## Docker stack (Cryptalias + Monero + Traefik)

This repo now includes:

- `Dockerfile`
- `docker-compose.yml`
- `config.example.yml`

### 1) Copy the sample config

```bash
cp config.example.yml config.yml
```

Important: keep `config.yml` writable. Cryptalias may generate keys and save them back into the file.

### 2) Prepare a Monero wallet

The sample stack mounts `./monero` into the wallet RPC container as `/wallets`.

That means you should:

- create your wallet files under `./monero`, and
- set `wallet_file:` and `wallet_password:` in `config.yml` to match

### 3) Configure the Monero daemon address

The compose file expects a daemon at `monerod:18081` by default. If yours lives elsewhere, set an environment variable:

```bash
export MONERO_DAEMON_ADDRESS=your-monerod-host:18081
```

You can also change the default credentials used by `monero-wallet-rpc`:

```bash
export MONERO_RPC_USER=cryptalias
export MONERO_RPC_PASS=change-me
```

If you change those, update the matching `username` and `password` in `config.yml` too.

### 4) Start the stack

```bash
docker compose up --build
```

The compose file includes a health check that hits:

- `http://127.0.0.1:8080/healthz`

### 5) Test it

With the provided Traefik config, the public endpoint will be routed via:

- `http://cryptalias.localhost`

For example:

```text
http://cryptalias.localhost/_cryptalias/resolve/xmr/me$cryptalias.localhost
```

### Notes on the sample stack

- Traefik routes the public port (`8080`)

## Minimal example config

This is the same shape as `config.example.yml`, shown inline for convenience:

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

## Client identity (very important)

Cryptalias needs a way to decide what "the same client" means. It uses this in two places:

- Per-client address stability (the TTL cache)
- Rate limiting

This is what `resolution.client_identity` controls.

### Strategies (what the options mean)

- `remote_address`: use the IP address of the direct TCP connection
- `xff`: use the first value from `X-Forwarded-For`
- `xff_ua`: use `X-Forwarded-For` plus a hashed user agent
- `header`: use a custom header you choose
- `header_ua`: use your custom header plus a hashed user agent

Notes:

- `xff` is the default because most deployments sit behind a reverse proxy
- If you use `header` or `header_ua`, you must set `client_identity.header`

### Copy/paste examples

#### Not behind a reverse proxy

If clients connect directly to Cryptalias, use `remote_address`:

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: remote_address
```

#### Behind Traefik

Traefik sets `X-Forwarded-For`, so `xff` is usually correct:

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff
    header: X-Forwarded-For
```

If you expect many users behind the same IP (for example, office NAT), you can tighten it a bit:

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff_ua
    header: X-Forwarded-For
```

#### Behind Caddy

Caddy also sets `X-Forwarded-For`, so the Traefik config works well here too:

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff
    header: X-Forwarded-For
```

#### Behind Nginx

For Nginx, the Cryptalias side still looks like this:

```yaml
resolution:
  ttl_seconds: 60
  client_identity:
    strategy: xff
    header: X-Forwarded-For
```

But you must also make sure Nginx forwards the header. A typical Nginx snippet looks like this:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

### Quick rule of thumb

- No proxy: `remote_address`
- Any normal proxy: `xff`
- Lots of shared IPs: `xff_ua`

## Static vs dynamic aliases

You have two modes per alias:

Static alias (fixed address)

```yaml
wallet:
  ticker: xmr
  address: 89abc...
```

Dynamic alias (fresh address from a wallet service)

```yaml
wallet:
  ticker: xmr
  address: ""
```

- If `address` is filled in, that exact address is returned.
- If `address` is empty, the wallet service is asked for an address.

## Per-alias account selection (important)

Account selection lives on the alias, not the endpoint.

That means you can do this:

```yaml
aliases:
  - alias: me
    wallet:
      ticker: xmr
      address: ""
      account_index: 0

  - alias: donations
    wallet:
      ticker: xmr
      address: ""
      account_index: 10
```

Optional alias routing hints you can set:

- `account_index`
- `account_id`
- `wallet_id`

They are forwarded to wallet services over gRPC, but are optional.

## External wallet services (gRPC plugins)

For external services, set:

```yaml
endpoint:
  type: external
  address: wallet-xmr:50051
```

Auth options if needed:

```yaml
endpoint:
  type: external
  address: wallet-xmr:50051
  token: "super-secret-token"
```

or:

```yaml
endpoint:
  type: external
  address: wallet-xmr:50051
  username: user
  password: pass
```

## Domain verification and status page

Cryptalias now checks your domains routinely, like a client would.

It verifies things like:

- `/.well-known/cryptalias` responds correctly
- `/_cryptalias/keys` contains the right key for the domain
- DNS resolves
- The `_cryptalias` TXT record matches your configured public key

Very important hosting rule:

- `https://yourdomain.com/.well-known/cryptalias` must be served by the domain being resolved
- `/_cryptalias/*` must be served by the Cryptalias host (for example `https://cryptalias.yourdomain.com/_cryptalias/...`)
- Correct example: discovery at `https://example.com/.well-known/cryptalias`
- Correct example: resolution at `https://cryptalias.example.com/_cryptalias/resolve/xmr/alice$example.com`
- Not required: `https://example.com/_cryptalias/resolve/...`

### Reverse proxy routing examples (the important bit)

Your proxy needs to do two different things:

- On each resolved domain, forward only `/.well-known/cryptalias` to Cryptalias
- On the Cryptalias host, forward `/_cryptalias/*` to Cryptalias

Below are minimal examples that show the intent clearly.

#### Traefik (labels)

These routers can sit on the `cryptalias` service.

```yaml
labels:
  - traefik.enable=true

  # 1) Discovery on the resolved domain
  - traefik.http.routers.cryptalias-wellknown.rule=Host(`example.com`) && Path(`/.well-known/cryptalias`)
  - traefik.http.routers.cryptalias-wellknown.entrypoints=websecure
  - traefik.http.routers.cryptalias-wellknown.tls=true
  - traefik.http.routers.cryptalias-wellknown.service=cryptalias-svc

  # 2) Resolution on the Cryptalias host
  - traefik.http.routers.cryptalias-public.rule=Host(`cryptalias.example.com`) && PathPrefix(`/_cryptalias/`)
  - traefik.http.routers.cryptalias-public.entrypoints=websecure
  - traefik.http.routers.cryptalias-public.tls=true
  - traefik.http.routers.cryptalias-public.service=cryptalias-svc

  # Service target
  - traefik.http.services.cryptalias-svc.loadbalancer.server.port=8080
```

#### Caddy

```caddyfile
example.com {
  handle /.well-known/cryptalias {
    reverse_proxy cryptalias:8080
  }
}

cryptalias.example.com {
  reverse_proxy cryptalias:8080
}
```

#### Nginx

```nginx
server {
  server_name example.com;

  location = /.well-known/cryptalias {
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

If a domain fails these checks, Cryptalias will _stop resolving aliases for that domain_ until it becomes healthy again.

You can see the current state here:

- `GET /_cryptalias/status`
- `GET /healthz` (simple liveness check for Docker/ops tooling)

Important difference:

- `/healthz` always returns `200` if the process is running
- `/_cryptalias/status` tells you whether domains are actually healthy

You can control how often the checks run:

```yaml
verify:
  interval_minutes: 5
```

I recommend leaving this at 5 minutes unless you have a good reason not to.

## Common mistakes (and how to fix them)

"unknown alias" (404)

- The domain in the URL must match `domains[].domain`
- The alias must exist under that domain
- The ticker must exist in `tokens[].tickers`
- The alias format must be `alias$domain` or `alias+tag$domain`

It keeps reloading but nothing changes

- Check logs for: `config reload rejected`
- That means validation failed and the old config is still active

Everything seems to come from the same client

- You probably have the wrong `client_identity.strategy` for your setup
- No proxy: use `remote_address`
- Behind a proxy: use `xff` (and make sure the proxy forwards the header)

Dynamic alias calls the wallet when you expected static

- Static requires `wallet.address` to be non-empty
- Empty string means dynamic

YAML error: "cannot unmarshal !!seq into cryptalias.WalletAddress"

- This usually means something that should be a map/object is written as a list
- For example, `wallet:` should look like:

```yaml
wallet:
  ticker: xmr
  address: 89abc...
```

...not:

```yaml
wallet:
  - ticker: xmr
    address: 89abc...
```

Signing or verification fails

- Make sure each domain has both `private_key` and `public_key`
- If keys were generated automatically, copy the DNS TXT record from the logs

Monero wallet RPC errors (500s)

- Make sure `monero-wallet-rpc` can reach a daemon
- Make sure the wallet file exists in `./monero`
- Make sure the RPC username/password match both compose and `config.yml`

## Notes on safety features

Two built-in protections are on by default:

1. Rate limiting: reduces scraping/spam
2. Per-client TTL cache: reduces address sniffing

These live under:

- `rate_limit`
- `resolution`

## Where to look next (if you are integrating)

- gRPC contract: `proto/cryptalias/v1/wallet_service.proto`
- Main entrypoint: `cmd/cryptalias/main.go`
- Core runtime: `internal/cryptalias/server.go`
