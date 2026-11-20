import assert from 'node:assert/strict';
import {
  createDecipheriv, createHash, createHmac, createPrivateKey,
  createPublicKey, diffieHellman, verify,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

const { login, manifest } = JSON.parse(readFileSync(new URL('./samples.json', import.meta.url)));
const bytes = (string) => Buffer.from(string, 'utf8');
const hex = (string) => Buffer.from(string, 'hex');
const cat = (...parts) => Buffer.concat(parts);
const empty = Buffer.alloc(0);
const base64 = (string) => {
  const decoded = Buffer.from(string, 'base64');
  assert.equal(decoded.toString('base64'), string);
  return decoded;
};
const keyId = (key) => createHash('sha256').update(key).digest('hex').slice(0, 16);
const publicKey = (prefix, key) => createPublicKey({ key: cat(hex(prefix), key), format: 'der', type: 'spki' });
const x25519 = (key) => {
  assert.equal(key.length, 32);
  return publicKey('302a300506032b656e032100', key);
};

// RFC 9180 §§4–7: Auth-mode X25519 / HKDF-SHA256 / ChaCha20-Poly1305.
// All expansions here fit in one SHA-256 block (one HMAC with counter 1).
const kemSuite = cat(bytes('KEM'), hex('0020'));
const hpkeSuite = cat(bytes('HPKE'), hex('002000010003'));
const hmac = (key, data) => createHmac('sha256', key).update(data).digest();
const extract = (suite, salt, label, input) => hmac(salt, cat(bytes('HPKE-v1'), suite, bytes(label), input));
const expand = (suite, prk, label, info, size) => {
  assert(size <= 32);
  return hmac(prk, cat(Buffer.from([0, size]), bytes('HPKE-v1'), suite, bytes(label), info, Buffer.from([1])))
    .subarray(0, size);
};
const envelope = JSON.parse(login.value);
assert.equal(envelope.v, 1);
const aad = JSON.parse(envelope.aad);
assert.equal(login.key, `${aad.home_box}.${aad.member_box}`);
assert.equal(BigInt(aad.generation), 9223372036854775807n);
const enc = base64(envelope.enc_b64);
const sender = base64(login.sender_public_b64);
const scalar = base64(login.recipient_private_b64);
assert.equal(scalar.length, 32);
const recipientPrivate = createPrivateKey({ key: cat(hex('302e020100300506032b656e04220420'), scalar), format: 'der', type: 'pkcs8' });
const recipient = createPublicKey(recipientPrivate).export({ type: 'spki', format: 'der' }).subarray(-32);
assert.equal(aad.sender_key_id, keyId(sender));
assert.equal(aad.recipient_key_id, keyId(recipient));
const dh = (publicKey) => diffieHellman({ privateKey: recipientPrivate, publicKey });
const eaePrk = extract(kemSuite, empty, 'eae_prk', cat(dh(x25519(enc)), dh(x25519(sender))));
const shared = expand(kemSuite, eaePrk, 'shared_secret', cat(enc, recipient, sender), 32);
const pskIdHash = extract(hpkeSuite, empty, 'psk_id_hash', empty);
const infoHash = extract(hpkeSuite, empty, 'info_hash', bytes('cortexkit/claustrum/hub-logins/v1'));
const context = cat(Buffer.from([2]), pskIdHash, infoHash);
const secret = extract(hpkeSuite, shared, 'secret', empty);
const key = expand(hpkeSuite, secret, 'key', context, 32);
const nonce = expand(hpkeSuite, secret, 'base_nonce', context, 12); // sequence zero
const ciphertext = base64(envelope.ciphertext_b64);
const open = (aadBytes) => {
  const decipher = createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aadBytes);
  decipher.setAuthTag(ciphertext.subarray(-16));
  return cat(decipher.update(ciphertext.subarray(0, -16)), decipher.final());
};
assert.deepEqual(open(bytes(envelope.aad)), bytes(login.plaintext));
assert.equal(JSON.parse(login.plaintext).logins[0].credential_id, 'oauth:example');
assert.throws(() => open(bytes(`${envelope.aad} `)));

const report = JSON.parse(manifest.value);
const body = JSON.parse(report.body);
assert.equal(report.v, 1);
assert.equal(manifest.key, body.box);
assert.equal(body.box, aad.home_box);
assert.equal(body.member, aad.home);
assert.equal(body.seq, Number.MAX_SAFE_INTEGER);
assert.equal(body.verdict, 'invalid');
assert.equal(body.reason, 'reported_invalid');
const writer = hex(manifest.writer_public_hex);
assert.equal(writer.length, 32);
assert.equal(report.key_id, keyId(writer));
const signature = base64(report.signature_b64);
const ed25519 = publicKey('302a300506032b6570032100', writer);
const domain = bytes('ck-vault-hub/manifest-active/v1\0');
assert(verify(null, cat(domain, bytes(report.body)), ed25519, signature));
assert(!verify(null, bytes(report.body), ed25519, signature));
assert(!verify(null, cat(domain, bytes(`${report.body} `)), ed25519, signature));
console.log('Verified the hub login seal and manifest signature, including exact-byte tamper checks.');
