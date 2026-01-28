export async function resolveAddress(ticker: string, alias: string): Promise<string> {
  if (!ticker || !alias) {
    throw new Error("ticker and alias are required");
  }

  const domain = parseDomain(alias);
  const configUrl = `https://${domain}/.well-known/cryptalias/configuration`;

  const config = await fetchJson(configUrl);
  const resolver = (config?.resolver?.resolver_endpoint || "").replace(/\/+$/, "");
  if (!resolver) {
    throw new Error("missing resolver_endpoint in configuration");
  }
  if (!config?.key) {
    throw new Error("missing key in configuration");
  }

  const resolveUrl = `${resolver}/_cryptalias/resolve/${encodeURIComponent(ticker)}/${encodeURIComponent(alias)}`;
  const jws = await fetchText(resolveUrl);
  const payload = await verifyJwsAndDecodePayload(jws, config.key);

  if (!payload?.address) {
    throw new Error("missing address in JWS payload");
  }
  enforceExpires(payload?.expires);

  return payload.address;
}

function parseDomain(value: string): string {
  const idx = value.lastIndexOf("$");
  if (idx === -1 || idx === value.length - 1) {
    throw new Error("alias must be in the format alias$domain");
  }
  return value.slice(idx + 1);
}

async function fetchJson(url: string): Promise<any> {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`request failed ${res.status}: ${await res.text()}`);
  }
  return res.json();
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { headers: { Accept: "application/jose" } });
  if (!res.ok) {
    throw new Error(`request failed ${res.status}: ${await res.text()}`);
  }
  return res.text();
}

function base64UrlToBase64(input: string): string {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return b64;
}

async function verifyJwsAndDecodePayload(jws: string, jwk: JsonWebKey): Promise<any> {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid JWS format");
  }
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlToBytes(parts[2]);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, signature, signingInput);
  if (!ok) {
    throw new Error("signature verification failed");
  }
  const payloadJson = new TextDecoder().decode(base64UrlToBytes(parts[1]));
  return JSON.parse(payloadJson);
}

function base64UrlToBytes(input: string): Uint8Array {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return new Uint8Array(Buffer.from(b64, "base64"));
}

function enforceExpires(value: string): void {
  if (!value) {
    throw new Error("missing expires in JWS payload");
  }
  const expires = new Date(value);
  if (Number.isNaN(expires.getTime())) {
    throw new Error("invalid expires in JWS payload");
  }
  if (expires.getTime() <= Date.now()) {
    throw new Error("resolved address has expired");
  }
}
