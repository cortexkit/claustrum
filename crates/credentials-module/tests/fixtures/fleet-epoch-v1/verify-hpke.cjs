// This verifier uses hpke-js, not the vault's Rust HPKE implementation.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { CipherSuite, HkdfSha256 } = require("@hpke/core");
const { DhkemX25519HkdfSha256 } = require("@hpke/dhkem-x25519");
const { Chacha20Poly1305 } = require("@hpke/chacha20poly1305");

async function main() {
  const samples = JSON.parse(fs.readFileSync(path.join(__dirname, "cases.json"), "utf8"));
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const decode = (text) => Buffer.from(text, "base64url");
  const recipientKey = await suite.kem.deserializePrivateKey(
    decode(samples.fixture_keys.recipient_private_key),
  );
  const senderPublicKey = await suite.kem.deserializePublicKey(
    decode(samples.fixture_keys.sender_public_key),
  );
  for (const sample of samples.wraps) {
    const context = await suite.createRecipientContext({
      recipientKey,
      senderPublicKey,
      enc: decode(sample.wrap.enc),
      info: Buffer.from(sample.info_utf8),
    });
    const plaintext = await context.open(decode(sample.wrap.ct), new Uint8Array());
    assert.deepEqual(Buffer.from(plaintext), Buffer.from(sample.plaintext_utf8), sample.name);
    console.log(`opened ${sample.name} (HPKE auth mode, exact plaintext bytes)`);
  }
  assert.equal(samples.wraps.length, 3);
  console.log("3 independent HPKE wrap checks passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
