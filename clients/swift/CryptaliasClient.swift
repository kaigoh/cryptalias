import Foundation

public enum CryptaliasError: Error {
  case invalidAlias
  case missingResolver
  case missingKey
  case invalidJws
  case missingAddress
  case requestFailed(Int, String)
}

public func resolveAddress(ticker: String, alias: String) async throws -> String {
  if ticker.isEmpty || alias.isEmpty {
    throw CryptaliasError.invalidAlias
  }
  let domain = try parseDomain(alias)
  let configUrl = URL(string: "https://\(domain)/.well-known/cryptalias/configuration")!

  let configData = try await httpGet(url: configUrl, accept: "application/json")
  let configJson = try JSONSerialization.jsonObject(with: configData) as? [String: Any]
  let resolver = ((configJson?["resolver"] as? [String: Any])?["resolver_endpoint"] as? String ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
  guard !resolver.isEmpty else { throw CryptaliasError.missingResolver }
  guard let jwk = configJson?["key"] as? [String: Any] else { throw CryptaliasError.missingKey }

  let resolveUrl = URL(string: "\(resolver)/_cryptalias/resolve/\(urlEncode(ticker))/\(urlEncode(alias))")!
  let jwsData = try await httpGet(url: resolveUrl, accept: "application/jose")
  let jws = String(decoding: jwsData, as: UTF8.self)
  let payload = try verifyJwsPayload(jws: jws, jwk: jwk)

  guard let address = payload["address"] as? String, !address.isEmpty else {
    throw CryptaliasError.missingAddress
  }
  guard let expires = payload["expires"] as? String else {
    throw CryptaliasError.invalidJws
  }
  try enforceExpires(expires)
  return address
}

public func verifyJwsPayload(jws: String, jwk: [String: Any]) throws -> [String: Any] {
  let parts = jws.split(separator: ".")
  guard parts.count == 3 else { throw CryptaliasError.invalidJws }

  guard let x = jwk["x"] as? String else { throw CryptaliasError.invalidJws }
  let publicKeyData = try base64UrlDecode(x)
  let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)

  let signingInput = "\(parts[0]).\(parts[1])"
  let signature = try base64UrlDecode(String(parts[2]))
  let ok = publicKey.isValidSignature(signature, for: Data(signingInput.utf8))
  if !ok {
    throw CryptaliasError.invalidJws
  }

  let payloadData = try base64UrlDecode(String(parts[1]))
  let obj = try JSONSerialization.jsonObject(with: payloadData)
  return obj as? [String: Any] ?? [:]
}

private func parseDomain(_ alias: String) throws -> String {
  guard let idx = alias.lastIndex(of: "$"), idx < alias.index(before: alias.endIndex) else {
    throw CryptaliasError.invalidAlias
  }
  return String(alias[alias.index(after: idx)...])
}

private func httpGet(url: URL, accept: String) async throws -> Data {
  var request = URLRequest(url: url)
  request.setValue(accept, forHTTPHeaderField: "Accept")
  let (data, response) = try await URLSession.shared.data(for: request)
  if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
    let body = String(decoding: data, as: UTF8.self)
    throw CryptaliasError.requestFailed(http.statusCode, body)
  }
  return data
}

private func base64UrlDecode(_ input: String) throws -> Data {
  var b64 = input.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
  while b64.count % 4 != 0 { b64.append("=") }
  if let data = Data(base64Encoded: b64) {
    return data
  }
  throw CryptaliasError.invalidJws
}

private func enforceExpires(_ value: String) throws {
  let formatter = ISO8601DateFormatter()
  formatter.formatOptions = [.withInternetDateTime]
  guard let date = formatter.date(from: value) else {
    throw CryptaliasError.invalidJws
  }
  if date <= Date() {
    throw CryptaliasError.invalidJws
  }
}

private func urlEncode(_ value: String) -> String {
  var allowed = CharacterSet.urlPathAllowed
  allowed.remove(charactersIn: "/")
  return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
}
