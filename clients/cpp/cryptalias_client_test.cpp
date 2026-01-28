#include "cryptalias_client.hpp"

#include <cassert>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>

int main() {
  std::ifstream file("../testdata/jws.json");
  assert(file.good());
  nlohmann::json data;
  file >> data;

  std::string payload = cryptalias::verify_jws_payload(data["jws"].get<std::string>(), data["jwk"].dump());
  auto payload_json = nlohmann::json::parse(payload);
  assert(payload_json["address"].get<std::string>() == data["payload"]["address"].get<std::string>());
  return 0;
}
