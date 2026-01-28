import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { resolveAddress } from "./index";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataPath = path.join(__dirname, "..", "testdata", "jws.json");
const data = JSON.parse(fs.readFileSync(dataPath, "utf8"));

function mockFetch(responses: Array<{ status?: number; body?: string }>) {
  return async () => {
    const entry = responses.shift();
    if (!entry) throw new Error("unexpected fetch");
    const status = entry.status ?? 200;
    const body = entry.body ?? "";
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => body,
      json: async () => JSON.parse(body),
    } as Response;
  };
}

test("resolveAddress verifies signature", async () => {
  const config = JSON.stringify({ resolver: { resolver_endpoint: "https://resolver.example" }, key: data.jwk });
  const fetch = mockFetch([{ body: config }, { body: data.jws }]);
  const origFetch = globalThis.fetch;
  globalThis.fetch = fetch as any;
  try {
    const address = await resolveAddress("xmr", "donations$example.com");
    assert.equal(address, data.payload.address);
  } finally {
    globalThis.fetch = origFetch;
  }
});
