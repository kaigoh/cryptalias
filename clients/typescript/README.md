# TypeScript client (HTTP only)

Minimal resolver helper (JWS verification required).

## Usage

```ts
import { resolveAddress } from "./index";

const address = await resolveAddress("xmr", "donations$example.com");
console.log(address);
```

Security note:
- `resolveAddress` verifies the JWS signature and enforces `expires` (see `PROTOCOL.md`).
