# Rust client (HTTP only)

Minimal resolver helper (JWS verification required).

## Usage

```rust
use cryptalias_client::resolve_address;

fn main() {
    let address = resolve_address("xmr", "donations$example.com").unwrap();
    println!("{}", address);
}
```

Security note:
- `resolve_address` verifies the JWS signature and enforces `expires` (see `PROTOCOL.md`).
