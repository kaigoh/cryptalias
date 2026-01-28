# Go client (HTTP only)

Minimal resolver helper (JWS verification required).

## Usage

```go
package main

import (
  "context"
  "fmt"

  "cryptalias-client"
)

func main() {
  address, err := cryptaliasclient.ResolveAddress(context.Background(), "xmr", "donations$example.com")
  if err != nil {
    panic(err)
  }
  fmt.Println(address)
}
```

Security note:
- `ResolveAddress` verifies the JWS signature and enforces `expires` (see `PROTOCOL.md`).
