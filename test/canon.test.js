'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const { rebuildCanonical, sha256Hex, verifyReceipt } = require('../lib/canon');

const issuer = crypto.generateKeyPairSync('ed25519');
const otherIssuer = crypto.generateKeyPairSync('ed25519');
const publicKey = issuer.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');
const otherKey = otherIssuer.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64');

function signedReceipt() {
  const receipt = {
    receipt_type: 'offline-test',
    issued_by: 'https://example.invalid',
    issued_at: '2026-01-01T00:00:00Z',
    agent_name: 'test-agent',
    owner_email_sha256: null,
    note: 'synthetic fixture',
    epoch: 0,
    signed: true,
    public_key_b64: publicKey,
  };
  receipt.canonical = rebuildCanonical(receipt);
  receipt.payload_sha256 = sha256Hex(receipt.canonical);
  receipt.signature = crypto.sign(null, Buffer.from(receipt.canonical), issuer.privateKey).toString('base64');
  return receipt;
}

function verify(receipt) {
  return verifyReceipt(receipt, { expectedPublicKeyB64: publicKey });
}

function uncheckedRejection(receipt, options) {
  const result = verifyReceipt(receipt, options);
  assert.equal(result.hash_ok, true);
  assert.equal(result.verdict, 'BAD_SIGNATURE');
  assert.equal(result.signature_checked, false);
  assert.equal(result.signature_ok, null);
}

test('a valid signature against the expected public key succeeds', () => {
  const result = verify(signedReceipt());
  assert.equal(result.verdict, 'OK');
  assert.equal(result.signature_checked, true);
  assert.equal(result.signature_ok, true);
});

test('the expected public key can verify a receipt without an embedded key', () => {
  const receipt = signedReceipt();
  delete receipt.public_key_b64;
  assert.equal(verify(receipt).verdict, 'OK');
});

test('a signed receipt missing both signature and public key fails closed', () => {
  const receipt = signedReceipt();
  delete receipt.signature;
  delete receipt.public_key_b64;
  uncheckedRejection(receipt);
});

test('a signed receipt missing its signature fails even with the expected key', () => {
  const receipt = signedReceipt();
  delete receipt.signature;
  uncheckedRejection(receipt, { expectedPublicKeyB64: publicKey });
});

test('a signature without any public key cannot pass on its matching payload hash', () => {
  const receipt = signedReceipt();
  delete receipt.public_key_b64;
  uncheckedRejection(receipt);
});

test('an empty signature is also an unchecked rejection', () => {
  uncheckedRejection({ ...signedReceipt(), signature: '' }, { expectedPublicKeyB64: publicKey });
});

test('a bad signature is rejected by Ed25519 verification', () => {
  const receipt = signedReceipt();
  const signature = Buffer.from(receipt.signature, 'base64');
  signature[0] ^= 1;
  receipt.signature = signature.toString('base64');
  const result = verify(receipt);
  assert.equal(result.verdict, 'BAD_SIGNATURE');
  assert.equal(result.signature_checked, true);
  assert.equal(result.signature_ok, false);
});

test('an embedded key cannot replace the expected public key', () => {
  const result = verify({ ...signedReceipt(), public_key_b64: otherKey });
  assert.equal(result.verdict, 'BAD_SIGNATURE');
  assert.equal(result.signature_ok, false);
  assert.match(result.signature_reason, /does not match published key/);
});

test('field tampering keeps its TAMPERED verdict even when a signature is missing', () => {
  const receipt = { ...signedReceipt(), agent_name: 'changed' };
  delete receipt.signature;
  const result = verify(receipt);
  assert.equal(result.verdict, 'TAMPERED');
  assert.equal(result.fields_match, false);
});

test('an unsigned hash commitment remains OK_UNSIGNED', () => {
  const receipt = { ...signedReceipt(), signed: false };
  delete receipt.signature;
  const result = verify(receipt);
  assert.equal(result.verdict, 'OK_UNSIGNED');
  assert.equal(result.signature_checked, false);
  assert.equal(result.signature_ok, null);
});

test('a signature attached to signed:false does not upgrade the commitment', () => {
  const result = verify({ ...signedReceipt(), signed: false });
  assert.equal(result.verdict, 'OK_UNSIGNED');
  assert.equal(result.signature_checked, false);
  assert.equal(result.signature_ok, null);
});
