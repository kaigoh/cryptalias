# C++ client (HTTP only)

Minimal resolver helper (JWS verification required).

Dependencies:
- libcurl
- nlohmann/json
- OpenSSL (for Ed25519 verification)

## Usage

```cpp
#include "cryptalias_client.hpp"
#include <iostream>

int main() {
  std::string address = cryptalias::resolve_address("xmr", "donations$example.com");
  std::cout << address << "\n";
}
```

Security note:
- `resolve_address` verifies the JWS signature and enforces `expires` (see `PROTOCOL.md`).
