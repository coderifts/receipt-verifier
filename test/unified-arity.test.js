'use strict';

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { _resetWarnedForTest } = require('../arity');
const { verifyReceipt } = require('../verify.js');
const { verifyExecutionGrant } = require('../verify-grant.js');
const { verifyExecutionAttestation } = require('../verify-attest.js');
const { verifyToolsetAttestation } = require('../verify-toolset.js');
const { verifyMonitoringAttestation } = require('../verify-monitor.js');
const { verifyBundle } = require('../verify-bundle.js');
const { verifyChain } = require('../verify.js');

const receipts = require('./vectors.json');
const grants = require('./grant-vectors.json');
const attests = require('./attest-vectors.json');
const toolsets = require('./toolset-vectors.json');
const monitors = require('./monitor-vectors.json');
const crypto = require('node:crypto');

const VALID_R = receipts.vectors.find((v) => v.name === 'valid_v4');
const ctxR = {
  publicKey: crypto.createPublicKey(receipts.public_key_pem),
  expectedKid: receipts.kid,
};
const VALID_G = grants.vectors.find((v) => v.name === 'EG-VALID');
const ctxG = {
  publicKey: crypto.createPublicKey(grants.public_key_pem),
  expectedKid: grants.kid,
};

describe('1129 unified (token, opts) shape', () => {
  beforeEach(() => _resetWarnedForTest());

  it('verifyReceipt accepts unified { ctx }', () => {
    const r = verifyReceipt(VALID_R.token, { ctx: ctxR });
    assert.equal(r.valid, true);
  });

  it('verifyExecutionGrant accepts unified { ctx, intended }', () => {
    const r = verifyExecutionGrant(VALID_G.token, {
      ctx: ctxG,
      intended: {
        operation: grants.operation,
        target_id: grants.target_id,
        audience: grants.audience,
        after_payload: grants.after_payload,
        receipt_token: grants.receipt,
      },
    });
    assert.equal(r.status, 'GRANT_CURRENT');
  });

  it('verifyExecutionAttestation accepts opts.ctx.registry', () => {
    const v = attests.vectors.find((x) => x.name === 'EG-A-VALID');
    const r = verifyExecutionAttestation(v.token, { ctx: { registry: attests.registry } });
    assert.equal(r.valid, true);
  });

  it('verifyToolsetAttestation accepts opts.ctx.registry', () => {
    const v = toolsets.vectors.find((x) => x.id === 'TS-A-VALID');
    const r = verifyToolsetAttestation(v.token, {
      ctx: { registry: toolsets.registry, entries: toolsets.entries },
    });
    assert.equal(r.valid, true);
  });

  it('verifyMonitoringAttestation accepts opts.ctx.registry', () => {
    const v = monitors.vectors.find((x) => x.name && x.name.startsWith('MON-A-VALID'))
      || monitors.vectors.find((x) => x.id === 'MON-A-VALID')
      || monitors.vectors[0];
    const r = verifyMonitoringAttestation(v.token, { ctx: { registry: monitors.registry } });
    assert.ok(r.status);
  });

  it('verifyBundle accepts unified { ctx }', () => {
    const r = verifyBundle({ v: 'cr.bundle.v1', slots: {} }, { ctx: ctxR });
    assert.equal(r.bundle, 'EMPTY');
  });

  it('verifyChain accepts unified { ctx }', () => {
    const r = verifyChain([VALID_R.token], { ctx: ctxR });
    assert.equal(typeof r.valid, 'boolean');
  });
});

describe('1129 3-ary wrappers warn once and forward', () => {
  beforeEach(() => _resetWarnedForTest());

  it('verifyReceipt(token, ctx, opts) still verifies and warns exactly once', () => {
    const warnings = [];
    const orig = process.emitWarning;
    process.emitWarning = (msg, type) => { warnings.push({ msg: String(msg), type }); };
    try {
      const a = verifyReceipt(VALID_R.token, ctxR, {});
      const b = verifyReceipt(VALID_R.token, ctxR, {});
      assert.equal(a.valid, true);
      assert.equal(b.valid, true);
      const dep = warnings.filter((w) => /verifyReceipt/.test(w.msg));
      assert.equal(dep.length, 1, `expected 1 warning, got ${dep.length}: ${JSON.stringify(dep)}`);
    } finally {
      process.emitWarning = orig;
    }
  });

  it('verifyExecutionGrant 3-ary wrapper forwards and warns exactly once', () => {
    const warnings = [];
    const orig = process.emitWarning;
    process.emitWarning = (msg, type) => { warnings.push({ msg: String(msg), type }); };
    try {
      const a = verifyExecutionGrant(VALID_G.token, ctxG, {});
      const b = verifyExecutionGrant(VALID_G.token, ctxG, {});
      assert.equal(a.valid, true);
      assert.equal(b.valid, true);
      const dep = warnings.filter((w) => /verifyExecutionGrant/.test(w.msg));
      assert.equal(dep.length, 1, `expected 1 warning, got ${dep.length}: ${JSON.stringify(dep)}`);
    } finally {
      process.emitWarning = orig;
    }
  });
});

describe('1128 throw stays on 2-ary verifiers', () => {
  it('verifyExecutionAttestation still throws on a third argument', () => {
    assert.throws(() => verifyExecutionAttestation('t', {}, {}));
  });
  it('verifyToolsetAttestation still throws on a third argument', () => {
    assert.throws(() => verifyToolsetAttestation('t', {}, {}));
  });
  it('verifyMonitoringAttestation still throws on a third argument', () => {
    assert.throws(() => verifyMonitoringAttestation('t', {}, {}));
  });
});
