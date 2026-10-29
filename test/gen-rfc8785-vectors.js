'use strict';
/**
 * Generates test/vectors/rfc8785.json (1.1.6). Every expected value is computed by THIS repository's
 * canonicalizer, verify.js canonicalJson; none is copied from an external source. The same inputs are then
 * run through the second implementation in this tree, verify.py canonical_json, and the result is recorded
 * in the file (cross_check) — agreement is measured, not assumed.
 *
 *   node test/gen-rfc8785-vectors.js
 */
const crypto = require('crypto'); const fs = require('fs'); const path = require('path');
const { spawnSync } = require('child_process');
const ROOT = path.join(__dirname, '..');
const { canonicalJson } = require(path.join(ROOT, 'verify.js'));
const cases = [
  ['key order: UTF-16 code units (BMP above the surrogates sorts after an astral key), non-ASCII and digit-like keys',
    '{"\\ufb33":1,"\\ud83d\\ude00":2,"a":3,"\\u00f6":4,"\\u20ac":5,"10":6,"2":7,"1":8,"B":9}'],
  ['key order: a prefix sorts first; case is code-unit order', '{"ab":1,"a":2,"aa":3,"A":4,"":5}'],
  ['nested objects and arrays; arrays keep their order', '{"b":[3,{"z":1,"a":[]}],"a":{"d":{"c":null},"c":[[2,1],[]]}}'],
  ['string escaping: controls, quote, backslash, slash unescaped, non-ASCII raw', '{"s":"\\u0000\\u0007\\b\\t\\n\\u000b\\f\\r\\u001f\\"\\\\/\\u007f\\u20ac\\ud83d\\ude00"}'],
  ['non-ASCII keys and values', '{"ключ":"значение","日本":"語","é":"e\\u0301"}'],
  ['integers', '{"zero":0,"one":1,"neg":-7,"max_safe":9007199254740991,"two53":9007199254740992}'],
  ['1e21 switches to exponent form; 1e20 does not', '{"a":1e20,"b":1e21,"c":123456789012345678901}'],
  ['1e-7 is exponent form; 1e-6 is not', '{"a":1e-7,"b":0.000001,"c":1.5e-7}'],
  ['-0 serializes as 0', '{"a":-0,"b":-0.0,"c":[-0]}'],
  ['0.1 and other decimals keep the shortest round-trip form', '{"a":0.1,"b":0.5,"c":3.14,"d":-2.5,"e":100.0,"f":1.0}'],
  ['booleans and null', '{"t":true,"f":false,"n":null,"l":[true,false,null]}'],
  ['empty object', '{}'],
  ['empty array', '[]'],
  ['empty containers nested', '{"o":{},"a":[],"n":[{},[]]}'],
  ['whitespace-free output from spaced input', ' {\n  "b" : 1 ,\n  "a" : [ 1 , 2 , { "y" : 2 , "x" : 1 } ]\n} '],
  ['top-level array of mixed values', '[3,"x",true,null,{"b":1,"a":2},[],-0,1e21]'],
];
const vectors = cases.map(([name, input_json], i) => {
  const canonical = canonicalJson(JSON.parse(input_json));
  return { id: `RFC8785-${String(i + 1).padStart(2, '0')}`, name, input_json, canonical,
    sha256: crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex') };
});
const PY = `import json, sys, importlib.util
spec = importlib.util.spec_from_file_location("verify", "verify.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(json.dumps([m.canonical_json(json.loads(t)) for t in json.load(sys.stdin)], ensure_ascii=False))`;
const py = spawnSync(process.env.PYTHON || 'python3', ['-c', PY], { cwd: ROOT, input: JSON.stringify(vectors.map((v) => v.input_json)), encoding: 'utf8' });
if (py.status !== 0) throw new Error(`verify.py cross-check did not run: ${py.stderr}`);
const pyOut = JSON.parse(py.stdout);
const differs = vectors.filter((v, i) => pyOut[i] !== v.canonical).map((v) => v.id);
const doc = {
  schema: 'coderifts.rfc8785-vectors.v1',
  description: 'RFC 8785 (JCS) canonicalization vectors. input_json is the JSON text of the input (kept as text so -0 and the number forms survive); canonical is the expected canonical string; sha256 is the hex sha256 of its UTF-8 bytes.',
  computed_by: 'verify.js canonicalJson (this repository)',
  provenance: 'Every expected value was computed with this repository\'s canonicalizer; none is copied from an external source.',
  cross_check: {
    implementation: 'verify.py canonical_json (this repository)',
    agrees: vectors.length - differs.length,
    of: vectors.length,
    differs,
    note: differs.length === 0
      ? 'verify.py produces byte-identical output on every vector (1.1.6: UTF-16 code-unit key order and ECMAScript Number serialization, as RFC 8785 specifies). Recomputed by this generator each run.'
      : 'Where verify.py differs, the expected value here is verify.js\'s: ECMAScript Number serialization and UTF-16 code-unit key order, which RFC 8785 specifies. The differences are verify.py\'s, measured by this generator.',
  },
  vectors,
};
fs.writeFileSync(path.join(ROOT, 'test', 'vectors', 'rfc8785.json'), `${JSON.stringify(doc, null, 2)}\n`);
console.log(`${vectors.length} vectors; verify.py agrees on ${doc.cross_check.agrees}, differs on ${differs.join(', ') || 'none'}`);
for (const v of vectors) console.log(v.id, '|', v.canonical);
