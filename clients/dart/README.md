# Dart client (HTTP only)

Minimal resolver helper (JWS verification required).

## Usage

```dart
import 'package:cryptalias_client/cryptalias_client.dart';

void main() async {
  final address = await resolveAddress('xmr', 'donations$example.com');
  print(address);
}
```

Security note:
- `resolveAddress` verifies the JWS signature and enforces `expires` (see `PROTOCOL.md`).
