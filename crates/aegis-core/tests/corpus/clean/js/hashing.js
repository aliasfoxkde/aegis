// Integrity hashing — high-entropy literals that are not credentials.
const crypto = require("crypto");

const BUILD_ID = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const CACHE_SALT = "Zm9vYmFyYmF6cXV1eGZvbyBiYXQgaGVsbG8gd29ybGQ=";

function digest(payload) {
  return crypto.createHash("sha256").update(payload).digest("hex");
}

module.exports = { digest, BUILD_ID, CACHE_SALT };
