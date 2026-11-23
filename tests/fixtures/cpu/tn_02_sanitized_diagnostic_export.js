// Hard negative: diagnostic redactor referencing sensitive field names ONLY to scrub them.
const REDACTED_MARKER = "[REDACTED]";

const SENSITIVE_FIELD_NAMES = new Set([
  "apiKey",
  "privateKey",
  "authorization",
  "password",
  "accessToken",
]);

const INLINE_CREDENTIAL_REGEXES = [
  /(Bearer\s+)[A-Za-z0-9._-]+/gi,
  /(apiKey|privateKey|password)\s*[:=]\s*["']?[^\s"',;]+["']?/gi,
];

function redactStringValue(rawText) {
  let clean = String(rawText);
  for (const pattern of INLINE_CREDENTIAL_REGEXES) {
    clean = clean.replace(pattern, `$1=${REDACTED_MARKER}`);
  }
  return clean;
}

function sanitizeDiagnosticPayload(record) {
  const output = {};
  for (const [key, value] of Object.entries(record || {})) {
    if (SENSITIVE_FIELD_NAMES.has(key)) {
      output[key] = REDACTED_MARKER;
    } else if (typeof value === "string") {
      output[key] = redactStringValue(value);
    } else {
      output[key] = value;
    }
  }
  return output;
}

module.exports = { sanitizeDiagnosticPayload, redactStringValue };
