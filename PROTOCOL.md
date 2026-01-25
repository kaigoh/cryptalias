# Cryptalias Protocol

This document explains how Cryptalias alias resolution works on the wire, and what clients and wallet integrations MUST and SHOULD do.

If you are just operating the server, most of this is handled for you. If you are writing a client, wallet plugin, or another server, read this end to end.

## Big picture

Cryptalias uses three public HTTP endpoints:

- `GET /.well-known/cryptalias/configuration`
- `GET /.well-known/cryptalias/keys`
- `GET /_cryptalias/resolve/{ticker}/{alias}`

And two operational endpoints:

- `GET /.well-known/cryptalias/status` (domain health)
- `GET /healthz` (process liveness)

The key idea is simple:

1) discover the domain key and resolver endpoint
2) resolve the alias
3) verify the signature
4) respect TTLs and rate limits

## Terminology

- Identifier format: `alias$domain` or `alias+tag$domain`
- Example: `donations+2026$example.com`
- Ticker: the asset symbol, such as `xmr` or `btc`

## Client algorithm (MUST / SHOULD)

Below is the reference client flow.

### 1) Parse and validate the identifier (MUST)

Clients MUST:

- Require the format `alias$domain` or `alias+tag$domain`
- Treat `alias`, `tag`, and `domain` as case-insensitive
- Reject invalid identifiers early

### 2) Discover the domain config (MUST)

Clients MUST fetch:

- `<scheme>://<domain>/.well-known/cryptalias/configuration`

Clients MUST:

- Send the request to the domain being resolved
- Validate the JSON response
- Ensure `domain` in the response matches the requested domain

Hosting rules (critical):

- `/.well-known/cryptalias/configuration` MUST be served on the resolved domain itself (example: `https://example.com/.well-known/cryptalias/configuration`)
- Resolver endpoints under `/_cryptalias/*` MUST be served on the Cryptalias host (example: `https://cryptalias.example.com/_cryptalias/resolve/xmr/alice$example.com`)
- Resolver endpoints do not need to be served on the resolved domain (counter-example: `https://example.com/_cryptalias/resolve/...`)

Reverse proxy routing examples (normative intent):

Traefik (labels on the Cryptalias service):

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.cryptalias-wellknown.rule=Host(`example.com`) && PathPrefix(`/.well-known/cryptalias/`)
  - traefik.http.routers.cryptalias-wellknown.entrypoints=websecure
  - traefik.http.routers.cryptalias-wellknown.tls=true
  - traefik.http.routers.cryptalias-wellknown.service=cryptalias-svc
  - traefik.http.routers.cryptalias-public.rule=Host(`cryptalias.example.com`) && PathPrefix(`/_cryptalias/`)
  - traefik.http.routers.cryptalias-public.entrypoints=websecure
  - traefik.http.routers.cryptalias-public.tls=true
  - traefik.http.routers.cryptalias-public.service=cryptalias-svc
  - traefik.http.services.cryptalias-svc.loadbalancer.server.port=8080
```

Caddy:

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

Nginx:

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

Clients SHOULD:

- Prefer HTTPS in production

The well-known response includes:

- The domain public key (as a JWK)
- The resolver endpoint

### 3) Resolve the alias (MUST)

Clients MUST call:

- `GET <resolver_endpoint>/_cryptalias/resolve/{ticker}/{alias}`

Important:

- `{alias}` is the full identifier including `$domain`
- Example:
  - `GET http://resolver.example/_cryptalias/resolve/xmr/donations$example.com`

### 4) Verify the signed response (MUST)

The resolve response is a compact JWS, not plain JSON.
The content type is:

- `application/jose`

Clients MUST:

1. Verify the JWS signature using the domain public key from `/.well-known/cryptalias/configuration`
2. Only trust the payload after signature verification succeeds

The expected payload shape (after verifying the JWS) is:

```json
{
  "version": 0,
  "ticker": "xmr",
  "address": "...",
  "expires": "2026-01-25T15:37:49Z",
  "nonce": "..."
}
```

Clients MUST also:

- Check that `ticker` matches the requested ticker
- Check that `expires` is still in the future

### 5) Respect TTLs and rate limits (MUST / SHOULD)

Clients MUST:

- Treat `expires` as authoritative
- Stop using a resolved address once it expires

Clients SHOULD:

- Cache successful resolutions until `expires`
- Avoid hammering the resolver
- Back off on errors

## Error handling and domain health

Cryptalias can gate a domain if it detects a misconfiguration.

### Resolution gating

If a domain is unhealthy, the resolver returns:

- `503 Service Unavailable`
- Body like: `503 domain unhealthy: ...`

Clients SHOULD:

- Treat this as a temporary error
- Back off and retry later
- Avoid falling back to unsigned data

### Status endpoints

Operators and advanced clients can check:

- `GET /.well-known/cryptalias/status`
  - Health for the resolved domain only
- `GET /healthz`
  - Simple liveness (always `200` if the process is up)

Important:

- `/healthz` is for containers and load balancers
- `/.well-known/cryptalias/status` is for humans and diagnostics

## Keys endpoint (important)

`/.well-known/cryptalias/keys` is domain-scoped and returns only that domain's key.

## Security notes for clients

Clients MUST:

- Verify signatures before displaying or using addresses
- Treat unsigned resolver responses as invalid
- Bind domain trust to the requested domain

Clients SHOULD:

- Prefer HTTPS in production
- Pin or cache domain keys with care
- Surface signature failures clearly to users

## Wallet integrations over gRPC

Cryptalias resolves dynamic aliases by calling a gRPC wallet service.

The contract lives here:

- `proto/cryptalias/v1/wallet_service.proto`

The service looks like this:

```proto
service WalletService {
  rpc GetAddress(WalletAddressRequest) returns (WalletAddressResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

### Request fields (important)

`WalletAddressRequest` includes:

- `ticker`, `alias`, `tag`, `domain` (always set)
- `account_index`, `account_id`, `wallet_id` (optional hints)

Everything except the parsed alias fields is optional by design.

### Auth metadata (important)

When using external gRPC endpoints, Cryptalias forwards auth via gRPC metadata:

- Bearer token:
  - `authorization: Bearer <token>`
- Basic auth:
  - `authorization: Basic <base64(username:password)>`

Your wallet service SHOULD:

- Expect the `authorization` metadata key
- Validate it if you enable auth

## Code generation (Go example)

If you are implementing a wallet service in Go, the simplest path is:

1) install the protoc plugins:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

2) generate code:

```bash
protoc \
  --go_out=paths=source_relative:. \
  --go-grpc_out=paths=source_relative:. \
  proto/cryptalias/v1/wallet_service.proto
```

This repo already includes generated Go code, so you only need to do this if you change the proto.

## Implementing the gRPC service

A wallet service MUST:

- Implement `GetAddress`
- Return a non-empty `address`

A wallet service SHOULD:

- Implement `Health`
- Fail closed (return errors) when it cannot produce a correct address
- Apply its own rate limits and abuse controls

## Configuring a gRPC wallet integration

To use an external wallet service, point the token endpoint at the gRPC server.

Example config:

```yaml
tokens:
  - name: Monero
    tickers: [xmr]
    endpoint:
      type: external
      address: wallet-xmr:50051
      token: "replace-me"
```

Notes:

- `address` is the gRPC target (host:port)
- For internal integrations, `type: internal` is used instead

## Docker compose example (external wallet service)

Below is a minimal pattern that wires an external wallet service into the existing stack.

```yaml
services:
  cryptalias:
    # ...existing config...
    depends_on:
      - wallet-xmr

  wallet-xmr:
    image: your-org/cryptalias-wallet-xmr:latest
    expose:
      - "50051"
```

Then in `config.yml`:

```yaml
tokens:
  - name: Monero
    tickers: [xmr]
    endpoint:
      type: external
      address: wallet-xmr:50051
      token: "replace-me"
```

## Compatibility expectations

If you are writing a client or wallet integration, these are the interoperability rules that matter most:

Clients MUST:

- Use `/.well-known/cryptalias/configuration` for discovery
- Verify JWS signatures
- Enforce `expires`

Wallet services MUST:

- Return a valid address for the request
- Treat optional fields as optional

Everything else is implementation detail.
