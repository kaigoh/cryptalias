import java.io.File
import org.json.JSONObject
import kotlin.test.assertEquals

fun main() {
  val data = JSONObject(File("../testdata/jws.json").readText())
  val payload = CryptaliasClient.verifyJwsPayload(data.getString("jws"), data.getJSONObject("jwk"))
  val payloadJson = JSONObject(payload)
  val expected = data.getJSONObject("payload").getString("address")
  assertEquals(expected, payloadJson.getString("address"))
}
