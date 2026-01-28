import 'dart:convert';
import 'dart:io';
import 'package:test/test.dart';
import 'package:cryptalias_client/cryptalias_client.dart';

Map<String, dynamic> loadTestData() {
  final file = File('../testdata/jws.json');
  final content = file.readAsStringSync();
  return jsonDecode(content) as Map<String, dynamic>;
}

void main() {
  test('verifyJwsPayload', () async {
    final data = loadTestData();
    final payload = await verifyJwsPayload(data['jws'] as String, data['jwk'] as Map<String, dynamic>);
    expect(payload['address'], equals(data['payload']['address']));
  });
}
