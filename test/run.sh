#!/usr/bin/env bash
#
# Cross-verify every vector through BOTH verify.js and verify.py.
# Fails (exit 1) on any disagreement between the two implementations, any
# mismatch against the expected {valid, reason}, or any exit-code divergence.
#
# No network: every check runs offline with the embedded public key (--key).
#
set -u
cd "$(dirname "$0")/.."

VECTORS="test/vectors.json"
PEM="$(mktemp -t rv_pub.XXXXXX)"
CHAIN_FILE="$(mktemp -t rv_chain.XXXXXX)"
LIVE_PEM="$(mktemp -t rv_livepub.XXXXXX)"
KEYS_FILE="$(mktemp -t rv_keys.XXXXXX)"
trap 'rm -f "$PEM" "$CHAIN_FILE" "$LIVE_PEM" "$KEYS_FILE"' EXIT

node -e "process.stdout.write(require('./$VECTORS').public_key_pem)" > "$PEM"
KID="$(node -e "process.stdout.write(require('./$VECTORS').kid)")"

PYTHON="${PYTHON:-python3}"
fails=0
checks=0

# jsonfield <json-string> <field>  -> prints field value ('' if absent)
jsonfield() {
  node -e "const o=JSON.parse(process.argv[1]); const v=o[process.argv[2]]; process.stdout.write(v===undefined?'':String(v))" "$1" "$2"
}

run_case() {
  local name="$1" token="$2" exp_valid="$3" exp_reason="$4"
  local pem="${5:-$PEM}" kid="${6:-$KID}"
  checks=$((checks + 1))

  out_js="$(node verify.js "$token" --key "$pem" --kid "$kid" 2>/dev/null)"; code_js=$?
  out_py="$("$PYTHON" verify.py "$token" --key "$pem" --kid "$kid" 2>/dev/null)"; code_py=$?

  local ok=1
  if [ "$out_js" != "$out_py" ]; then
    echo "FAIL  $name: JS/PY OUTPUT DIFFER"
    echo "  js: $out_js"
    echo "  py: $out_py"
    ok=0
  fi
  if [ "$code_js" != "$code_py" ]; then
    echo "FAIL  $name: exit codes differ (js=$code_js py=$code_py)"
    ok=0
  fi
  local got_valid got_reason
  got_valid="$(jsonfield "$out_js" valid)"
  got_reason="$(jsonfield "$out_js" reason)"
  if [ "$got_valid" != "$exp_valid" ]; then
    echo "FAIL  $name: valid expected=$exp_valid got=$got_valid"
    ok=0
  fi
  if [ -n "$exp_reason" ] && [ "$got_reason" != "$exp_reason" ]; then
    echo "FAIL  $name: reason expected=$exp_reason got=$got_reason"
    ok=0
  fi
  # exit-code sanity vs valid
  local want_code=1; [ "$exp_valid" = "true" ] && want_code=0
  if [ "$code_js" != "$want_code" ]; then
    echo "FAIL  $name: exit code expected=$want_code got=$code_js"
    ok=0
  fi

  if [ "$ok" = "1" ]; then
    echo "ok    $name  (js==py; valid=$got_valid${got_reason:+ reason=$got_reason})"
  else
    fails=$((fails + 1))
  fi
}

echo "== standalone vectors =="
n="$(node -e "process.stdout.write(String(require('./$VECTORS').vectors.length))")"
for i in $(seq 0 $((n - 1))); do
  name="$(node -e "process.stdout.write(require('./$VECTORS').vectors[$i].name)")"
  token="$(node -e "process.stdout.write(require('./$VECTORS').vectors[$i].token)")"
  ev="$(node -e "process.stdout.write(String(require('./$VECTORS').vectors[$i].expected.valid))")"
  er="$(node -e "const r=require('./$VECTORS').vectors[$i].expected.reason; process.stdout.write(r||'')")"
  run_case "$name" "$token" "$ev" "$er"
done

echo
echo "== 3-link chain =="
node -e "require('./$VECTORS').chain.tokens.forEach(t=>process.stdout.write(t+'\n'))" > "$CHAIN_FILE"
checks=$((checks + 1))
out_js="$(node verify.js --chain "$CHAIN_FILE" --key "$PEM" --kid "$KID" 2>/dev/null)"; code_js=$?
out_py="$("$PYTHON" verify.py --chain "$CHAIN_FILE" --key "$PEM" --kid "$KID" 2>/dev/null)"; code_py=$?
exp_valid="$(node -e "process.stdout.write(String(require('./$VECTORS').chain.expected.valid))")"
exp_first="$(node -e "process.stdout.write(require('./$VECTORS').chain.expected.first)")"

chain_ok=1
if [ "$out_js" != "$out_py" ]; then
  echo "FAIL  chain: JS/PY OUTPUT DIFFER"; echo "  js: $out_js"; echo "  py: $out_py"; chain_ok=0
fi
if [ "$code_js" != "$code_py" ]; then
  echo "FAIL  chain: exit codes differ (js=$code_js py=$code_py)"; chain_ok=0
fi
got_valid="$(jsonfield "$out_js" valid)"
got_first="$(node -e "process.stdout.write(JSON.parse(process.argv[1]).chain.first)" "$out_js")"
if [ "$got_valid" != "$exp_valid" ]; then echo "FAIL  chain: valid expected=$exp_valid got=$got_valid"; chain_ok=0; fi
if [ "$got_first" != "$exp_first" ]; then echo "FAIL  chain: first expected=$exp_first got=$got_first"; chain_ok=0; fi
if [ "$chain_ok" = "1" ]; then
  echo "ok    chain  (js==py; valid=$got_valid first=$got_first)"
else
  fails=$((fails + 1))
fi

echo
echo "== negative chain (break the middle prev link) =="
# Reverse links 1 and 2 so token[1].prev no longer matches sha256(token[0]).
node -e "const t=require('./$VECTORS').chain.tokens.slice(); [t[1],t[2]]=[t[2],t[1]]; t.forEach(x=>process.stdout.write(x+'\n'))" > "$CHAIN_FILE"
checks=$((checks + 1))
out_js="$(node verify.js --chain "$CHAIN_FILE" --key "$PEM" --kid "$KID" 2>/dev/null)"; code_js=$?
out_py="$("$PYTHON" verify.py --chain "$CHAIN_FILE" --key "$PEM" --kid "$KID" 2>/dev/null)"; code_py=$?
neg_ok=1
[ "$out_js" = "$out_py" ] || { echo "FAIL  neg-chain: JS/PY OUTPUT DIFFER"; echo "  js: $out_js"; echo "  py: $out_py"; neg_ok=0; }
gv="$(jsonfield "$out_js" valid)"
[ "$gv" = "false" ] || { echo "FAIL  neg-chain: expected valid=false got=$gv"; neg_ok=0; }
[ "$code_js" = "1" ] && [ "$code_py" = "1" ] || { echo "FAIL  neg-chain: exit code expected 1 (js=$code_js py=$code_py)"; neg_ok=0; }
if [ "$neg_ok" = "1" ]; then echo "ok    neg-chain  (js==py; broken link detected, valid=false)"; else fails=$((fails + 1)); fi

echo
echo "== live production vector (real prod key) =="
node -e "process.stdout.write(require('./$VECTORS').live.public_key_pem)" > "$LIVE_PEM"
LIVE_KID="$(node -e "process.stdout.write(require('./$VECTORS').live.kid)")"
ln="$(node -e "process.stdout.write(String(require('./$VECTORS').live.vectors.length))")"
for i in $(seq 0 $((ln - 1))); do
  name="$(node -e "process.stdout.write(require('./$VECTORS').live.vectors[$i].name)")"
  token="$(node -e "process.stdout.write(require('./$VECTORS').live.vectors[$i].token)")"
  ev="$(node -e "process.stdout.write(String(require('./$VECTORS').live.vectors[$i].expected.valid))")"
  er="$(node -e "const r=require('./$VECTORS').live.vectors[$i].expected.reason; process.stdout.write(r||'')")"
  run_case "$name" "$token" "$ev" "$er" "$LIVE_PEM" "$LIVE_KID"
done

echo
echo "== registry resolution (--keys) =="
# Build a one-entry registry from the live block; resolve the live receipt by kid.
node -e "const v=require('./$VECTORS').live; process.stdout.write(JSON.stringify({keys:[{kid:v.kid,public_key_pem:v.public_key_pem,status:'active',valid_from:'2026-07-01T00:00:00.000Z'}]}))" > "$KEYS_FILE"
live_token="$(node -e "process.stdout.write(require('./$VECTORS').live.vectors[0].token)")"
checks=$((checks + 1))
out_js="$(node verify.js "$live_token" --keys "$KEYS_FILE" 2>/dev/null)"; code_js=$?
out_py="$("$PYTHON" verify.py "$live_token" --keys "$KEYS_FILE" 2>/dev/null)"; code_py=$?
keys_ok=1
[ "$out_js" = "$out_py" ] || { echo "FAIL  keys: JS/PY OUTPUT DIFFER"; echo "  js: $out_js"; echo "  py: $out_py"; keys_ok=0; }
gv="$(jsonfield "$out_js" valid)"
[ "$gv" = "true" ] || { echo "FAIL  keys: expected valid=true got=$gv"; keys_ok=0; }
[ "$code_js" = "0" ] && [ "$code_py" = "0" ] || { echo "FAIL  keys: exit code expected 0 (js=$code_js py=$code_py)"; keys_ok=0; }
# unknown kid in registry -> unknown_kid
checks=$((checks + 1))
out_js2="$(node verify.js "$live_token" --keys "$KEYS_FILE" --kid absent-k9 2>/dev/null)"
out_py2="$("$PYTHON" verify.py "$live_token" --keys "$KEYS_FILE" --kid absent-k9 2>/dev/null)"
[ "$out_js2" = "$out_py2" ] || { echo "FAIL  keys-guard: JS/PY OUTPUT DIFFER"; keys_ok=0; }
gr="$(jsonfield "$out_js2" reason)"
[ "$gr" = "unknown_kid" ] || { echo "FAIL  keys-guard: expected unknown_kid got=$gr"; keys_ok=0; }
if [ "$keys_ok" = "1" ]; then echo "ok    keys  (js==py; live receipt resolved by kid; --kid guard rejects)"; else fails=$((fails + 1)); fi

echo
echo "checks=$checks fails=$fails"
[ "$fails" = "0" ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES: $fails"; exit 1; }
