# Cryptalias client examples (HTTP only)

These are drop-in helper functions for resolving an alias to a wallet address. JWS verification is required.

Important:
- The resolver response is a signed JWS. Each client verifies the signature and enforces `expires` (see `PROTOCOL.md`).

Each client:
1) Parses `alias$domain`
2) Fetches `/.well-known/cryptalias/configuration` from the domain
3) Calls `/_cryptalias/resolve/{ticker}/{alias}` on the resolver
4) Decodes the JWS payload and returns `address`

Languages:
- JavaScript: `clients/javascript`
- TypeScript: `clients/typescript`
- Go: `clients/go`
- Rust: `clients/rust`
- Dart: `clients/dart`
- C++: `clients/cpp`
- Swift: `clients/swift`
- Kotlin: `clients/kotlin`
