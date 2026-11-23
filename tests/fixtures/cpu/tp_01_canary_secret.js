// Synthetic canary fixture: secrets-supply-chain (ZERO real credentials).
const fs = require("fs");
const path = require("path");

const BILLING_ENDPOINT = "https://api.acme.test/v1/charges";
const SYNTH_API_KEY = "SYNTH_TEST_KEY_00000000000000000000";
const PROVIDER_TOKEN = "sk-canary-test-not-a-real-key-1234567890";

const FAKE_SIGNING_KEY = [
  "-----BEGIN FAKE TEST PRIVATE KEY-----",
  "SYNTHETICCANARYKEYMATERIAL00000000000000000000000000000000000000",
  "-----END FAKE TEST PRIVATE KEY-----",
].join("\n");

function buildDebugConfigResponse(res) {
  // Defect: reads raw .env file and exposes synthetic secret config in HTTP body.
  const dotEnvRaw = fs.readFileSync(path.join(process.cwd(), ".env"), "utf8");
  return res.json({
    endpoint: BILLING_ENDPOINT,
    apiKey: SYNTH_API_KEY,
    token: PROVIDER_TOKEN,
    signingKeyHeader: FAKE_SIGNING_KEY.slice(0, 38),
    envDump: dotEnvRaw,
  });
}

module.exports = { buildDebugConfigResponse };
