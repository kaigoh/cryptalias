export async function resolveAddress(ticker, alias) {
  if (!ticker || !alias) {
    throw new Error("ticker and alias are required");
  }
  const tickerClean = normalizeTicker(ticker);
  const prefix = parseTickerPrefix(alias);
  if (prefix && prefix !== tickerClean) {
    throw new Error(`ticker prefix "${prefix}" does not match "${tickerClean}"`);
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

  const resolveUrl = `${resolver}/_cryptalias/resolve/${encodeURIComponent(tickerClean)}/${encodeURIComponent(alias)}`;
  const jws = await fetchText(resolveUrl);
  const payload = await verifyJwsAndDecodePayload(jws, config.key);

  if (!payload?.address) {
    throw new Error("missing address in JWS payload");
  }
  enforceExpires(payload?.expires);

  return payload.address;
}

function parseDomain(value) {
  const idx = value.lastIndexOf("$");
  if (idx === -1 || idx === value.length - 1) {
    throw new Error("alias must be in the format [ticker:]alias$domain");
  }
  return value.slice(idx + 1);
}

function parseTickerPrefix(value) {
  const idx = value.lastIndexOf("$");
  if (idx === -1 || idx === value.length - 1) {
    throw new Error("alias must be in the format [ticker:]alias$domain");
  }
  const left = value.slice(0, idx);
  const colon = left.indexOf(":");
  if (colon === -1) return "";
  if (colon === 0 || colon === left.length - 1 || left.indexOf(":", colon + 1) !== -1) {
    throw new Error("invalid format (expected [ticker:]alias[+tag]$domain)");
  }
  return left.slice(0, colon).toLowerCase();
}

function normalizeTicker(value) {
  return String(value || "").trim().toLowerCase();
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`request failed ${res.status}: ${await res.text()}`);
  }
  return res.json();
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { Accept: "application/jose" } });
  if (!res.ok) {
    throw new Error(`request failed ${res.status}: ${await res.text()}`);
  }
  return res.text();
}

function base64UrlDecode(input) {
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  if (typeof atob === "function") {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  const bufferCtor = globalThis.Buffer;
  if (bufferCtor) {
    const buf = bufferCtor.from(b64, "base64");
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  throw new Error("base64 decoder not available");
}

async function verifyJwsAndDecodePayload(jws, jwk) {
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid JWS format");
  }
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlDecode(parts[2]);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, signature, signingInput);
  if (!ok) {
    throw new Error("signature verification failed");
  }
  const payloadJson = new TextDecoder().decode(base64UrlDecode(parts[1]));
  return JSON.parse(payloadJson);
}

function enforceExpires(value) {
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
