import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.Base64
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import org.json.JSONObject

object CryptaliasClient {
  @JvmStatic
  fun resolveAddress(ticker: String, alias: String): String {
    if (ticker.isEmpty() || alias.isEmpty()) {
      throw IllegalArgumentException("ticker and alias are required")
    }

    val tickerClean = normalizeTicker(ticker)
    val prefix = parseTickerPrefix(alias)
    if (prefix.isNotEmpty() && prefix != tickerClean) {
      throw IllegalArgumentException("ticker prefix \"$prefix\" does not match \"$tickerClean\"")
    }
    val domain = parseDomain(alias)
    val configUrl = URL("https://$domain/.well-known/cryptalias/configuration")
    val configJson = JSONObject(httpGet(configUrl, "application/json"))
    val resolver = configJson.getJSONObject("resolver").getString("resolver_endpoint").trimEnd('/')
    if (resolver.isEmpty()) {
      throw IllegalStateException("missing resolver_endpoint in configuration")
    }
    if (!configJson.has("key")) {
      throw IllegalStateException("missing key in configuration")
    }

    val resolveUrl = URL("$resolver/_cryptalias/resolve/${urlEncode(tickerClean)}/${urlEncode(alias)}")
    val jws = httpGet(resolveUrl, "application/jose")
    val payloadJson = JSONObject(verifyJwsPayload(jws, configJson.getJSONObject("key")))

    val address = payloadJson.optString("address", "")
    if (address.isEmpty()) {
      throw IllegalStateException("missing address in JWS payload")
    }
    enforceExpires(payloadJson.optString("expires", ""))
    return address
  }

  @JvmStatic
  fun verifyJwsPayload(jws: String, jwk: JSONObject): String {
    val parts = jws.split(".")
    if (parts.size != 3) throw IllegalArgumentException("invalid JWS format")
    val signingInput = "${parts[0]}.${parts[1]}".toByteArray()
    val signatureBytes = Base64.getUrlDecoder().decode(parts[2])
    val x = jwk.getString("x")
    val pubBytes = Base64.getUrlDecoder().decode(x)

    val spkiPrefix = byteArrayOf(
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    )
    val encoded = spkiPrefix + pubBytes
    val keySpec = X509EncodedKeySpec(encoded)
    val keyFactory = KeyFactory.getInstance("Ed25519")
    val publicKey = keyFactory.generatePublic(keySpec)

    val verifier = Signature.getInstance("Ed25519")
    verifier.initVerify(publicKey)
    verifier.update(signingInput)
    if (!verifier.verify(signatureBytes)) {
      throw IllegalArgumentException("signature verification failed")
    }

    val payloadBytes = Base64.getUrlDecoder().decode(parts[1])
    return String(payloadBytes)
  }

  private fun enforceExpires(value: String) {
    if (value.isEmpty()) {
      throw IllegalStateException("missing expires in JWS payload")
    }
    val expires = java.time.Instant.parse(value)
    if (!expires.isAfter(java.time.Instant.now())) {
      throw IllegalStateException("resolved address has expired")
    }
  }

  private fun parseDomain(alias: String): String {
    val idx = alias.lastIndexOf('$')
    if (idx == -1 || idx == alias.length - 1) {
      throw IllegalArgumentException("alias must be in the format [ticker:]alias$domain")
    }
    return alias.substring(idx + 1)
  }

  private fun parseTickerPrefix(alias: String): String {
    val idx = alias.lastIndexOf('$')
    if (idx == -1 || idx == alias.length - 1) {
      throw IllegalArgumentException("alias must be in the format [ticker:]alias$domain")
    }
    val left = alias.substring(0, idx)
    val colon = left.indexOf(':')
    if (colon == -1) return ""
    if (colon == 0 || colon == left.length - 1 || left.indexOf(':', colon + 1) != -1) {
      throw IllegalArgumentException("invalid format (expected [ticker:]alias[+tag]$domain)")
    }
    return left.substring(0, colon).lowercase()
  }

  private fun httpGet(url: URL, accept: String): String {
    val conn = url.openConnection() as HttpURLConnection
    conn.requestMethod = "GET"
    conn.setRequestProperty("Accept", accept)
    val code = conn.responseCode
    val reader = BufferedReader(InputStreamReader(if (code in 200..299) conn.inputStream else conn.errorStream))
    val body = reader.readText()
    reader.close()
    if (code !in 200..299) {
      throw IllegalStateException("request failed $code: $body")
    }
    return body
  }

  private fun urlEncode(value: String): String {
    return URLEncoder.encode(value, "UTF-8")
  }

  private fun normalizeTicker(value: String): String {
    return value.trim().lowercase()
  }
}
