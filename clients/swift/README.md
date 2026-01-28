# Swift client (HTTP only)

Minimal resolver helper (JWS verification required).

## Usage

```swift
let address = try await resolveAddress(ticker: "xmr", alias: "donations$example.com")
print(address)
```

Security note:
- `resolveAddress` verifies the JWS signature and enforces `expires` (see `PROTOCOL.md`).
