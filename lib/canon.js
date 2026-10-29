'use strict';

const crypto = require('crypto');

// bl-canon-v0: exactly these keys, in this order, missing values as null,
// then compact JSON.stringify. Spec: GET /api/receipt
const SIGNED_FIELDS = [
  'receipt_type',
  'issued_by',
  'issued_at',
  'agent_name',
  'owner_email_sha256',
  'note',
  'epoch',
];

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function compactStringify(obj) {
  return JSON.stringify(obj);
}

function rebuildCanonical(receipt) {
  const built = {};
  for (const key of SIGNED_FIELDS) {
    built[key] = Object.prototype.hasOwnProperty.call(receipt, key)
      ? receipt[key]
      : null;
  }
  return compactStringify(built);
}

function rebuildJcs(receipt) {
  const built = {};
  for (const key of SIGNED_FIELDS) {
    built[key] = Object.prototype.hasOwnProperty.call(receipt, key)
      ? receipt[key]
      : null;
  }
  const ordered = {};
  for (const key of Object.keys(built).sort()) {
    ordered[key] = built[key];
  }
  return compactStringify(ordered);
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function verifyEd25519(messageUtf8, signatureB64, publicKeyB64) {
  if (!signatureB64 || !publicKeyB64) {
    return { checked: false, ok: null, reason: 'missing signature or public key' };
  }
  try {
    const sig = Buffer.from(signatureB64, 'base64');
    const raw = Buffer.from(publicKeyB64, 'base64');
    if (raw.length !== 32) {
      return { checked: true, ok: false, reason: `public key length ${raw.length}, expected 32` };
    }
    if (sig.length !== 64) {
      return { checked: true, ok: false, reason: `signature length ${sig.length}, expected 64` };
    }
    const der = Buffer.concat([SPKI_PREFIX, raw]);
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    const ok = crypto.verify(null, Buffer.from(messageUtf8, 'utf8'), key, sig);
    return { checked: true, ok, reason: ok ? 'valid' : 'Ed25519 reject' };
  } catch (err) {
    return { checked: true, ok: false, reason: err.message };
  }
}

function extractReceipt(input) {
  if (input == null) throw new Error('no receipt');
  if (typeof input === 'string') {
    const trimmed = input.trim();
    return JSON.parse(trimmed);
  }
  if (typeof input === 'object') {
    if (input.receipt && typeof input.receipt === 'object' && !input.payload_sha256) {
      return input.receipt;
    }
    return input;
  }
  throw new Error('receipt must be an object or JSON string');
}

/**
 * Offline verification. Never phones the issuer.
 * A valid hash with signed:false is a hash commitment, not a signature.
 * jcs_sha256 is an unsigned interop digest — never treated as a second signature.
 */
function verifyReceipt(input, options = {}) {
  const receipt = extractReceipt(input);
  const expectedKey = options.expectedPublicKeyB64 || null;

  const rebuilt = rebuildCanonical(receipt);
  const providedCanonical = typeof receipt.canonical === 'string' ? receipt.canonical : null;
  const fieldsMatch = providedCanonical == null ? null : rebuilt === providedCanonical;
  const payload = sha256Hex(providedCanonical != null ? providedCanonical : rebuilt);
  const hashOk = typeof receipt.payload_sha256 === 'string'
    ? payload === receipt.payload_sha256
    : false;

  const rebuiltJcs = rebuildJcs(receipt);
  const jcsHash = sha256Hex(rebuiltJcs);
  const jcsOk = typeof receipt.jcs_sha256 === 'string' ? jcsHash === receipt.jcs_sha256 : null;

  const signed = receipt.signed === true;
  let signature = { checked: false, ok: null, reason: 'not signed' };
  if (signed) {
    const key = receipt.public_key_b64 || expectedKey;
    if (expectedKey && receipt.public_key_b64 && expectedKey !== receipt.public_key_b64) {
      signature = { checked: true, ok: false, reason: 'embedded public key does not match published key' };
    } else {
      signature = verifyEd25519(
        providedCanonical != null ? providedCanonical : rebuilt,
        receipt.signature,
        key
      );
    }
  } else if (receipt.signature) {
    signature = { checked: false, ok: null, reason: 'signed:false but signature present — ignored' };
  }

  let verdict = 'OK';
  if (!hashOk || fieldsMatch === false) verdict = 'TAMPERED';
  else if (signed && (signature.checked !== true || signature.ok !== true)) verdict = 'BAD_SIGNATURE';
  else if (!signed) verdict = 'OK_UNSIGNED';

  return {
    verdict,
    fields_match: fieldsMatch,
    hash_ok: hashOk,
    signature_ok: signature.ok,
    signature_checked: signature.checked,
    signature_reason: signature.reason,
    signed,
    signing_status: receipt.signing_status || (signed ? 'LIVE' : 'DARK'),
    jcs_ok: jcsOk,
    jcs_note: 'unsigned interop digest — not a second signature',
    rebuilt_canonical: rebuilt,
    rebuilt_payload_sha256: payload,
    rebuilt_jcs: rebuiltJcs,
    rebuilt_jcs_sha256: jcsHash,
    receipt_type: receipt.receipt_type || null,
    agent_name: receipt.agent_name || null,
    issued_at: receipt.issued_at || null,
    issued_by: receipt.issued_by || null,
    what_it_is_not: 'Not identity, reputation, or authorization. Content commitment only.',
  };
}

module.exports = {
  SIGNED_FIELDS,
  rebuildCanonical,
  rebuildJcs,
  sha256Hex,
  verifyEd25519,
  verifyReceipt,
  extractReceipt,
};
