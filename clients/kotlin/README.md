# Kotlin client (HTTP only)

Minimal resolver helper (JWS verification required).

Dependency:
- org.json (JSON parsing)

## Usage

```kotlin
val address = CryptaliasClient.resolveAddress("xmr", "donations$example.com")
println(address)
```

Security note:
- `resolveAddress` verifies the JWS signature and enforces `expires` (see `PROTOCOL.md`).
