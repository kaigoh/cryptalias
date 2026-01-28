import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;

Future<String> resolveAddress(String ticker, String alias) async {
  if (ticker.isEmpty || alias.isEmpty) {
    throw Exception('ticker and alias are required');
  }

  final domain = _parseDomain(alias);
  final configUrl = Uri.parse('https://$domain/.well-known/cryptalias/configuration');
  final configRes = await http.get(configUrl, headers: {'Accept': 'application/json'});
  if (configRes.statusCode < 200 || configRes.statusCode >= 300) {
    throw Exception('request failed ${configRes.statusCode}: ${configRes.body}');
  }
  final configJson = jsonDecode(configRes.body) as Map<String, dynamic>;
  final resolver = (configJson['resolver']?['resolver_endpoint'] ?? '').toString().replaceAll(RegExp(r'/+$'), '');
  final jwk = configJson['key'] as Map<String, dynamic>?;
  if (resolver.isEmpty) {
    throw Exception('missing resolver_endpoint in configuration');
  }
  if (jwk == null) {
    throw Exception('missing key in configuration');
  }

  final resolveUrl = Uri.parse(
    '$resolver/_cryptalias/resolve/${Uri.encodeComponent(ticker)}/${Uri.encodeComponent(alias)}',
  );
  final resolveRes = await http.get(resolveUrl, headers: {'Accept': 'application/jose'});
  if (resolveRes.statusCode < 200 || resolveRes.statusCode >= 300) {
    throw Exception('request failed ${resolveRes.statusCode}: ${resolveRes.body}');
  }

  final payload = await verifyJwsPayload(resolveRes.body, jwk);
  final address = payload['address']?.toString() ?? '';
  if (address.isEmpty) {
    throw Exception('missing address in JWS payload');
  }
  _enforceExpires(payload['expires']?.toString());
  return address;
}

Future<Map<String, dynamic>> verifyJwsPayload(String jws, Map<String, dynamic> jwk) =>
    _verifyJwsPayload(jws, jwk);

String _parseDomain(String alias) {
  final idx = alias.lastIndexOf(r'$');
  if (idx == -1 || idx == alias.length - 1) {
    throw Exception('alias must be in the format alias\$domain');
  }
  return alias.substring(idx + 1);
}

List<int> _base64UrlDecode(String input) {
  var padded = input.replaceAll('-', '+').replaceAll('_', '/');
  while (padded.length % 4 != 0) {
    padded += '=';
  }
  return base64.decode(padded);
}

Future<Map<String, dynamic>> _verifyJwsPayload(String jws, Map<String, dynamic> jwk) async {
  final parts = jws.split('.');
  if (parts.length != 3) {
    throw Exception('invalid JWS format');
  }
  final signingInput = utf8.encode('${parts[0]}.${parts[1]}');
  final signature = _base64UrlDecode(parts[2]);
  final publicKey = SimplePublicKey(_base64UrlDecode(jwk['x'] as String), type: KeyPairType.ed25519);
  final algorithm = Ed25519();
  final sig = Signature(signature, publicKey: publicKey);
  final ok = await algorithm.verify(signingInput, signature: sig);
  if (!ok) {
    throw Exception('signature verification failed');
  }
  final payloadJson = utf8.decode(_base64UrlDecode(parts[1]));
  return jsonDecode(payloadJson) as Map<String, dynamic>;
}

void _enforceExpires(String? value) {
  if (value == null || value.isEmpty) {
    throw Exception('missing expires in JWS payload');
  }
  final expires = DateTime.tryParse(value);
  if (expires == null) {
    throw Exception('invalid expires in JWS payload');
  }
  if (!expires.toUtc().isAfter(DateTime.now().toUtc())) {
    throw Exception('resolved address has expired');
  }
}
