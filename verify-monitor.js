#!/usr/bin/env node
'use strict';

/*
 * CodeRifts cr.monitor.attest.v1 monitoring-attestation verifier -- Node >= 20,
 * zero dependencies (node:crypto only). Sibling of verify.js / verify-grant.js /
 * verify-attest.js / verify-toolset.js.
 *
 * Usage:
 *   node verify-monitor.js <token> --keys <file|url>
 *        [--decision-id <id>] [--receipt-digest sha256:…]
 *
 * WHY THIS EXISTS (1115). The seven MON-A-* cases live in the CodeRifts app's
 * adapter-acceptance case file as scenario NAMES with no runner anywhere -- the app's
 * subjects implement only `decide` and `tool_selection`, so nothing executed them, in
 * either repository. cr.monitor.attest.v1 was the one signed artifact of the five with
 * no public offline verifier. This is that verifier, and test/monitor-vectors.json
 * carries the seven ids as runnable vectors.
 *
 * --keys is REQUIRED. Monitoring keys are CUSTOMER-HELD; this verifier never fetches
 * CodeRifts. Same registry shape as .well-known/coderifts-keys.json.
 *
 * Output: JSON { valid, status, reason?, payload? } to stdout -- byte-identical to
 * verify_monitor.py. Exit codes: 0 valid (MON_ATTEST_VALID |
 * MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE), 1 otherwise, 2 usage error.
 *
 * Retired-key rule is HISTORICAL (receipt class): retired kid + observed_at inside
 * [valid_from, retired_at) → MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE. Contrast grants:
 * retired → UNKNOWN_KEY, because a grant is live permission and this is a statement
 * about what was observed.
 *
 * Honesty: a valid attestation proves a holder of the monitoring key asserts that a
 * decision's monitoring payload reached a sink with this delivery_status at this time.
 * It does NOT prove the sink acted on it, that a human read it, that the underlying
 * decision is still current, or -- when delivery_status is `not_delivered` -- that
 * anything was delivered at all. MON-A-NOT-DELIVERED is VALID on purpose: the
 * signature over an honest "not delivered" is exactly as valid as over a delivery.
 */

const crypto = require('node:crypto');
const {
  resolveExecutorKey,
  isIssueTimeWithinKeyWindow,
  loadRegistryDocument,
} = require('./verify-attest.js');

const ATTEST_VERSION = 'cr.monitor.attest.v1';
const SIGNING_PREFIX = 'crmonattest.v1';
const ENVELOPE_TAG = 'cr.monitor.attest.v1';

const DELIVERY_STATUSES = Object.freeze(['delivered_acked', 'sent_unacked', 'not_delivered']);
const SINK_KINDS = Object.freeze(['callback', 'http']);

const REQUIRED_FIELDS = Object.freeze([
  'kid', 'decision_id', 'receipt_digest', 'delivery_status', 'sink_kind', 'observed_at',
]);
const OPTIONAL_STRINGS = Object.freeze(['ack_digest']);
const ALLOWED_KEYS = new Set(['v', ...REQUIRED_FIELDS, ...OPTIONAL_STRINGS, 'attempt_count', 'meta']);

const STATUSES = Object.freeze({
  MON_ATTEST_VALID: 'MON_ATTEST_VALID',
  MON_ATTEST_INVALID_SIGNATURE: 'MON_ATTEST_INVALID_SIGNATURE',
  MON_ATTEST_UNKNOWN_KEY: 'MON_ATTEST_UNKNOWN_KEY',
  MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE: 'MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE',
  MON_ATTEST_MALFORMED: 'MON_ATTEST_MALFORMED',
  MON_ATTEST_UNBOUND: 'MON_ATTEST_UNBOUND',
});

function scalar(v) {
  return v == null ? '' : String(v);
}

/** MIRRORED from the app kernel: keys sorted, values stringified. */
function canonicalMeta(meta) {
  const keys = Object.keys(meta).sort();
  const o = {};
  for (const k of keys) o[k] = meta[k];
  return JSON.stringify(o);
}

/** MIRRORED byte-for-byte from coderifts-app/src/verdict-core/monitoring-attestation.js:72. */
function signingInput(body) {
  const parts = [
    SIGNING_PREFIX,
    scalar(body.kid),
    scalar(body.decision_id),
    scalar(body.receipt_digest),
    scalar(body.delivery_status),
    body.ack_digest != null && String(body.ack_digest).length > 0 ? String(body.ack_digest) : '',
    scalar(body.sink_kind),
    scalar(body.observed_at),
    body.attempt_count != null ? String(body.attempt_count) : '',
  ];
  if (body.meta && typeof body.meta === 'object') parts.push(canonicalMeta(body.meta));
  return parts.join('|');
}

function fail(status, reason, payload) {
  const out = { valid: false, status };
  if (reason) out.reason = reason;
  if (payload !== undefined) out.payload = payload;
  return out;
}

function parseMonitorToken(token) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  const segments = token.split('|');
  if (segments.length !== 4) {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'malformed_structure' };
  }
  if (segments[0] !== ENVELOPE_TAG) {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'unsupported_version' };
  }
  let payload;
  try {
    payload = JSON.parse(Buffer.from(segments[2], 'base64url').toString('utf8'));
  } catch {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (!payload || typeof payload !== 'object') {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'bad_json' };
  }
  if (payload.v !== ATTEST_VERSION) {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'unsupported_version', payload };
  }
  for (const k of REQUIRED_FIELDS) {
    if (typeof payload[k] !== 'string' || payload[k].length === 0) {
      return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'missing_field', payload };
    }
  }
  // An additive field is REFUSED, not ignored — same rule as the other four envelopes.
  for (const k of Object.keys(payload)) {
    if (!ALLOWED_KEYS.has(k)) {
      return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'unknown_field', payload };
    }
  }
  if (!DELIVERY_STATUSES.includes(payload.delivery_status)) {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'bad_delivery_status', payload };
  }
  if (!SINK_KINDS.includes(payload.sink_kind)) {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'bad_sink_kind', payload };
  }
  if (segments[1] !== payload.kid) {
    return { ok: false, status: STATUSES.MON_ATTEST_MALFORMED, reason: 'kid_mismatch', payload };
  }
  return { ok: true, payload, sig: segments[3] };
}

/** A `|` inside a signed field would make the preimage ambiguous. */
function hasDelimiter(body) {
  for (const k of [...REQUIRED_FIELDS, ...OPTIONAL_STRINGS]) {
    if (typeof body[k] === 'string' && body[k].includes('|')) return true;
  }
  return false;
}

/**
 * @param {string} token
 * @param {object} opts
 * @param {object} opts.registry  customer-pinned { keys: [...] }
 * @param {object} [opts.intended]  { decision_id?: string, receipt_digest?: string }
 */
function verifyMonitoringAttestation(token, opts = {}) {
  // 1128 — a third argument is a caller error, guarded from day one rather than after a
  // wrong run. verifyReceipt and verifyExecutionGrant are (token, ctx, opts); this one is
  // (token, opts), and a dropped third argument would silently skip the cross-check below
  // and grade a mismatched attestation MON_ATTEST_VALID.
  if (arguments.length > 2) {
    throw new Error(
      'verifyMonitoringAttestation(token, opts) — pass intended via opts.intended. '
      + `Received ${arguments.length} arguments; the third would be ignored and the cross-check `
      + 'would silently not run, grading a mismatched attestation MON_ATTEST_VALID.',
    );
  }

  const parsed = parseMonitorToken(token);
  if (!parsed.ok) return fail(parsed.status, parsed.reason, parsed.payload);
  const payload = parsed.payload;

  if (hasDelimiter(payload)) {
    return fail(STATUSES.MON_ATTEST_INVALID_SIGNATURE, 'delimiter_in_field', payload);
  }

  const resolved = resolveExecutorKey(opts.registry, payload.kid);
  if (!resolved) return fail(STATUSES.MON_ATTEST_UNKNOWN_KEY, 'unknown_kid', payload);

  let ok = false;
  try {
    ok = crypto.verify(
      null,
      Buffer.from(signingInput(payload), 'utf8'),
      // resolveExecutorKey returns an already-built KeyObject on `publicKey` — NOT a PEM string
      // on `public_key_pem`. Measured: the PEM field name is what the registry JSON uses, the
      // resolver hands back the parsed key. Using the wrong one throws and reads as
      // signature_error, which looks like a bad signature rather than a caller mistake.
      resolved.publicKey,
      Buffer.from(parsed.sig, 'base64url'),
    );
  } catch {
    return fail(STATUSES.MON_ATTEST_INVALID_SIGNATURE, 'signature_error', payload);
  }
  if (!ok) return fail(STATUSES.MON_ATTEST_INVALID_SIGNATURE, 'signature_mismatch', payload);

  // HISTORICAL retired-key rule: this is a statement about what was observed, not live
  // permission, so a retired key still proves the statement was made inside its window.
  let retiredHistorical = false;
  if (resolved.status === 'retired') {
    if (!isIssueTimeWithinKeyWindow(payload.observed_at, resolved)) {
      return fail(STATUSES.MON_ATTEST_UNKNOWN_KEY, 'retired_key_outside_window', payload);
    }
    retiredHistorical = true;
  }

  const intended = opts.intended && typeof opts.intended === 'object' ? opts.intended : null;
  if (intended) {
    if (intended.decision_id != null && String(intended.decision_id).length > 0
        && String(intended.decision_id) !== payload.decision_id) {
      return fail(STATUSES.MON_ATTEST_UNBOUND, 'decision_id_mismatch', payload);
    }
    if (intended.receipt_digest != null && String(intended.receipt_digest).length > 0
        && String(intended.receipt_digest) !== payload.receipt_digest) {
      return fail(STATUSES.MON_ATTEST_UNBOUND, 'receipt_digest_mismatch', payload);
    }
  }

  return {
    valid: true,
    status: retiredHistorical
      ? STATUSES.MON_ATTEST_RETIRED_KEY_VALID_AT_ISSUE
      : STATUSES.MON_ATTEST_VALID,
    payload,
  };
}

function failUsage(msg) {
  process.stderr.write(`${msg}\n`);
  process.exit(2);
}

async function main() {
  const argv = process.argv.slice(2);
  const token = argv.find((a) => !a.startsWith('--'));
  const take = (flag) => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : null;
  };
  if (!token) failUsage('usage: verify-monitor.js <token> --keys <file|url> [--decision-id id] [--receipt-digest sha256:…]');
  const keys = take('--keys');
  if (!keys) failUsage('--keys is required: monitoring keys are customer-held; this verifier never fetches CodeRifts.');

  let registry;
  try {
    registry = await loadRegistryDocument(keys);
  } catch (e) {
    failUsage(`could not load --keys ${keys}: ${e.message}`);
  }

  const intended = {};
  const did = take('--decision-id');
  const rd = take('--receipt-digest');
  if (did) intended.decision_id = did;
  if (rd) intended.receipt_digest = rd;

  const result = verifyMonitoringAttestation(token, {
    registry,
    ...(Object.keys(intended).length > 0 ? { intended } : {}),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(result.valid ? 0 : 1);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`${e && e.message ? e.message : e}\n`);
    process.exit(2);
  });
}

module.exports = {
  verifyMonitoringAttestation,
  parseMonitorToken,
  signingInput,
  ATTEST_VERSION,
  SIGNING_PREFIX,
  ENVELOPE_TAG,
  STATUSES,
  DELIVERY_STATUSES,
  SINK_KINDS,
};
