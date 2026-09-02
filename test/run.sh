#!/usr/bin/env bash
#
# Cross-verify every vector through BOTH verify.js and verify.py.
# Fails (exit 1) on any disagreement between the two implementations, any
# mismatch against the expected {valid, reason}, or any exit-code divergence.
#
# No network: every check runs offline with the embedded public key (--key).
#
# 1134: `pipefail` joins `-u`. `-e` was TRIED AND REVERTED, measured rather than assumed.
#
# WHY -e CANNOT GO HERE. This harness deliberately runs commands that are EXPECTED to exit
# non-zero — every negative vector (tampered_fp, neg-chain, the MALFORMED classes) is a case where
# verify.js correctly exits 1 — and it captures those codes to compare js against py:
#     out_js="$(node cli.js "$token" ... )"; code_js=$?
# There are 14 such capture sites. Under `set -e` the first negative vector aborts the run: the
# measured result was an exit at `valid_v3_empty_reg`, four checks in, with 61 checks never
# reaching the comparison. Making -e work would mean appending `|| true` to all 14, which converts
# an explicit exit-code comparison into a silenced one — the opposite of what this gate is for.
#
# `pipefail` is kept: it costs nothing here and closes the pipe-swallowing case if one is ever
# added. The original concern stands and is NOT closed by this line: a future check written
# without an explicit `if` would still fail silently. Every check today is if-guarded.
set -uo pipefail
cd "$(dirname "$0")/.."

VECTORS="test/vectors.json"
PEM="$(mktemp -t rv_pub.XXXXXX)"
CHAIN_FILE="$(mktemp -t rv_chain.XXXXXX)"
LIVE_PEM="$(mktemp -t rv_livepub.XXXXXX)"
KEYS_FILE="$(mktemp -t rv_keys.XXXXXX)"
ENV_FILE="$(mktemp -t rv_env.XXXXXX)"
ENV_TAMPERED="$(mktemp -t rv_envt.XXXXXX)"
RETIRED_KEYS="$(mktemp -t rv_retired.XXXXXX)"
trap 'rm -f "$PEM" "$CHAIN_FILE" "$LIVE_PEM" "$KEYS_FILE" "$ENV_FILE" "$ENV_TAMPERED" "$RETIRED_KEYS"' EXIT

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
  local pem="${5:-$PEM}" kid="${6:-$KID}" exp_status="${7:-}"
  checks=$((checks + 1))

  out_js="$(node cli.js "$token" --key "$pem" --kid "$kid" 2>/dev/null)"; code_js=$?
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
  if [ -n "$exp_status" ]; then
    local got_status; got_status="$(jsonfield "$out_js" status)"
    if [ "$got_status" != "$exp_status" ]; then
      echo "FAIL  $name: status expected=$exp_status got=$got_status"
      ok=0
    fi
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
  es="$(node -e "const s=require('./$VECTORS').vectors[$i].expected.status; process.stdout.write(s||'')")"
  run_case "$name" "$token" "$ev" "$er" "$PEM" "$KID" "$es"
done

echo
echo "== 3-link chain =="
node -e "require('./$VECTORS').chain.tokens.forEach(t=>process.stdout.write(t+'\n'))" > "$CHAIN_FILE"
checks=$((checks + 1))
out_js="$(node cli.js --chain "$CHAIN_FILE" --key "$PEM" --kid "$KID" 2>/dev/null)"; code_js=$?
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
out_js="$(node cli.js --chain "$CHAIN_FILE" --key "$PEM" --kid "$KID" 2>/dev/null)"; code_js=$?
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
out_js="$(node cli.js "$live_token" --keys "$KEYS_FILE" 2>/dev/null)"; code_js=$?
out_py="$("$PYTHON" verify.py "$live_token" --keys "$KEYS_FILE" 2>/dev/null)"; code_py=$?
keys_ok=1
[ "$out_js" = "$out_py" ] || { echo "FAIL  keys: JS/PY OUTPUT DIFFER"; echo "  js: $out_js"; echo "  py: $out_py"; keys_ok=0; }
gv="$(jsonfield "$out_js" valid)"
[ "$gv" = "true" ] || { echo "FAIL  keys: expected valid=true got=$gv"; keys_ok=0; }
[ "$code_js" = "0" ] && [ "$code_py" = "0" ] || { echo "FAIL  keys: exit code expected 0 (js=$code_js py=$code_py)"; keys_ok=0; }
# unknown kid in registry -> unknown_kid
checks=$((checks + 1))
out_js2="$(node cli.js "$live_token" --keys "$KEYS_FILE" --kid absent-k9 2>/dev/null)"
out_py2="$("$PYTHON" verify.py "$live_token" --keys "$KEYS_FILE" --kid absent-k9 2>/dev/null)"
[ "$out_js2" = "$out_py2" ] || { echo "FAIL  keys-guard: JS/PY OUTPUT DIFFER"; keys_ok=0; }
gr="$(jsonfield "$out_js2" reason)"
[ "$gr" = "unknown_kid" ] || { echo "FAIL  keys-guard: expected unknown_kid got=$gr"; keys_ok=0; }
if [ "$keys_ok" = "1" ]; then echo "ok    keys  (js==py; live receipt resolved by kid; --kid guard rejects)"; else fails=$((fails + 1)); fi

echo
echo "== v4 envelope binding (--envelope) =="
bind_token="$(node -e "process.stdout.write(require('./$VECTORS').bind.token)")"
node -e "process.stdout.write(JSON.stringify(require('./$VECTORS').bind.envelope))" > "$ENV_FILE"
node -e "const e={...require('./$VECTORS').bind.envelope, decision:'ALLOW'}; process.stdout.write(JSON.stringify(e))" > "$ENV_TAMPERED"
bind_ok=1
checks=$((checks + 1))
oj="$(node cli.js "$bind_token" --key "$PEM" --kid "$KID" --envelope "$ENV_FILE" 2>/dev/null)"; cj=$?
op="$("$PYTHON" verify.py "$bind_token" --key "$PEM" --kid "$KID" --envelope "$ENV_FILE" 2>/dev/null)"; cp=$?
[ "$oj" = "$op" ] || { echo "FAIL  bind-ok: JS/PY DIFFER"; echo " js:$oj"; echo " py:$op"; bind_ok=0; }
[ "$(jsonfield "$oj" status)" = "VERIFIED_CURRENT" ] || { echo "FAIL  bind-ok: status=$(jsonfield "$oj" status)"; bind_ok=0; }
[ "$cj" = "0" ] && [ "$cp" = "0" ] || { echo "FAIL  bind-ok: exit (js=$cj py=$cp)"; bind_ok=0; }
checks=$((checks + 1))
oj="$(node cli.js "$bind_token" --key "$PEM" --kid "$KID" --envelope "$ENV_TAMPERED" 2>/dev/null)"
op="$("$PYTHON" verify.py "$bind_token" --key "$PEM" --kid "$KID" --envelope "$ENV_TAMPERED" 2>/dev/null)"
[ "$oj" = "$op" ] || { echo "FAIL  bind-tampered: JS/PY DIFFER"; echo " js:$oj"; echo " py:$op"; bind_ok=0; }
[ "$(jsonfield "$oj" reason)" = "body_hash_mismatch" ] || { echo "FAIL  bind-tampered: reason=$(jsonfield "$oj" reason)"; bind_ok=0; }
if [ "$bind_ok" = "1" ]; then echo "ok    bind  (js==py; envelope binds; tampered envelope -> body_hash_mismatch)"; else fails=$((fails + 1)); fi

echo
echo "== retired-key rule (--keys with retired_at) =="
node -e "process.stdout.write(JSON.stringify(require('./$VECTORS').retired.registry))" > "$RETIRED_KEYS"
tok_valid="$(node -e "process.stdout.write(require('./$VECTORS').retired.token_valid_at_issue)")"
tok_after="$(node -e "process.stdout.write(require('./$VECTORS').retired.token_after_retire)")"
retired_ok=1
checks=$((checks + 1))
oj="$(node cli.js "$tok_valid" --keys "$RETIRED_KEYS" 2>/dev/null)"; cj=$?
op="$("$PYTHON" verify.py "$tok_valid" --keys "$RETIRED_KEYS" 2>/dev/null)"; cp=$?
[ "$oj" = "$op" ] || { echo "FAIL  retired-valid: JS/PY DIFFER"; echo " js:$oj"; echo " py:$op"; retired_ok=0; }
[ "$(jsonfield "$oj" status)" = "RETIRED_KEY_VALID_AT_ISSUE" ] || { echo "FAIL  retired-valid: status=$(jsonfield "$oj" status)"; retired_ok=0; }
[ "$cj" = "0" ] && [ "$cp" = "0" ] || { echo "FAIL  retired-valid: exit (js=$cj py=$cp)"; retired_ok=0; }
checks=$((checks + 1))
oj="$(node cli.js "$tok_after" --keys "$RETIRED_KEYS" 2>/dev/null)"; cj=$?
op="$("$PYTHON" verify.py "$tok_after" --keys "$RETIRED_KEYS" 2>/dev/null)"; cp=$?
[ "$oj" = "$op" ] || { echo "FAIL  retired-after: JS/PY DIFFER"; echo " js:$oj"; echo " py:$op"; retired_ok=0; }
[ "$(jsonfield "$oj" status)" = "KEY_RETIRED_AFTER_SIGNING" ] || { echo "FAIL  retired-after: status=$(jsonfield "$oj" status)"; retired_ok=0; }
[ "$cj" = "1" ] && [ "$cp" = "1" ] || { echo "FAIL  retired-after: exit (js=$cj py=$cp)"; retired_ok=0; }
if [ "$retired_ok" = "1" ]; then echo "ok    retired  (js==py; valid-at-issue accepted; after-retire rejected)"; else fails=$((fails + 1)); fi

echo
echo "== 1079 B key lifecycle (retired_at / revoked_at, additive) =="
LIFE_KEYS="$(mktemp -t rv_life.XXXXXX)"
trap 'rm -f "$PEM" "$CHAIN_FILE" "$LIVE_PEM" "$KEYS_FILE" "$ENV_FILE" "$ENV_TAMPERED" "$RETIRED_KEYS" "$LIFE_KEYS"' EXIT
ln="$(node -e "process.stdout.write(String((require('./$VECTORS').lifecycle||{vectors:[]}).vectors.length))")"
life_ok=1
if [ "$ln" = "0" ]; then
  echo "FAIL  lifecycle vectors missing — run: node test/gen-vectors.js"
  life_ok=0
  fails=$((fails + 1))
else
  for i in $(seq 0 $((ln - 1))); do
    name="$(node -e "process.stdout.write(require('./$VECTORS').lifecycle.vectors[$i].name)")"
    token="$(node -e "process.stdout.write(require('./$VECTORS').lifecycle.vectors[$i].token)")"
    ev="$(node -e "process.stdout.write(String(require('./$VECTORS').lifecycle.vectors[$i].expected.valid))")"
    es="$(node -e "process.stdout.write(require('./$VECTORS').lifecycle.vectors[$i].expected.status||'')")"
    er="$(node -e "const r=require('./$VECTORS').lifecycle.vectors[$i].expected.reason; process.stdout.write(r||'')")"
    node -e "process.stdout.write(JSON.stringify(require('./$VECTORS').lifecycle.vectors[$i].registry))" > "$LIFE_KEYS"
    checks=$((checks + 1))
    out_js="$(node cli.js "$token" --keys "$LIFE_KEYS" 2>/dev/null)"; code_js=$?
    out_py="$("$PYTHON" verify.py "$token" --keys "$LIFE_KEYS" 2>/dev/null)"; code_py=$?
    lok=1
    if [ "$out_js" != "$out_py" ]; then
      echo "FAIL  $name: JS/PY OUTPUT DIFFER"
      echo "  js: $out_js"
      echo "  py: $out_py"
      lok=0
    fi
    [ "$code_js" = "$code_py" ] || { echo "FAIL  $name: exit codes differ (js=$code_js py=$code_py)"; lok=0; }
    [ "$(jsonfield "$out_js" valid)" = "$ev" ] || { echo "FAIL  $name: valid expected=$ev got=$(jsonfield "$out_js" valid)"; lok=0; }
    [ "$(jsonfield "$out_js" status)" = "$es" ] || { echo "FAIL  $name: status expected=$es got=$(jsonfield "$out_js" status)"; lok=0; }
    if [ -n "$er" ] && [ "$(jsonfield "$out_js" reason)" != "$er" ]; then
      echo "FAIL  $name: reason expected=$er got=$(jsonfield "$out_js" reason)"
      lok=0
    fi
    want_code=1; [ "$ev" = "true" ] && want_code=0
    [ "$code_js" = "$want_code" ] || { echo "FAIL  $name: exit expected=$want_code got=$code_js"; lok=0; }
    if [ "$lok" = "1" ]; then
      echo "ok    $name  (js==py; status=$(jsonfield "$out_js" status))"
    else
      life_ok=0
      fails=$((fails + 1))
    fi
  done
fi
checks=$((checks + 1))
if node --test test/key-lifecycle.test.js >/dev/null; then
  echo "ok    key-lifecycle.test.js"
else
  echo "FAIL  key-lifecycle.test.js"
  fails=$((fails + 1))
fi
rm -f "$LIFE_KEYS"

echo
echo "== require-smoke + ID104 leeway (js) =="
checks=$((checks + 1))
if node test/require-smoke.js; then
  echo "ok    require-smoke"
else
  echo "FAIL  require-smoke"
  fails=$((fails + 1))
fi

echo
echo "== ID131 default-fetch dual-shape (js) =="
checks=$((checks + 1))
if node test/fetch-shapes.js; then
  echo "ok    fetch-shapes.js"
else
  echo "FAIL  fetch-shapes.js"
  fails=$((fails + 1))
fi

echo
echo "== ID104 leeway (py) =="
checks=$((checks + 1))
if "$PYTHON" test/test_leeway.py; then
  echo "ok    test_leeway.py"
else
  echo "FAIL  test_leeway.py"
  fails=$((fails + 1))
fi

echo
echo "== ID131 default-fetch dual-shape (py) =="
checks=$((checks + 1))
if "$PYTHON" test/test_fetch_shapes.py; then
  echo "ok    test_fetch_shapes.py"
else
  echo "FAIL  test_fetch_shapes.py"
  fails=$((fails + 1))
fi

GRANT_VECTORS="test/grant-vectors.json"
GRANT_PEM="$(mktemp -t rv_gpub.XXXXXX)"
GRANT_KEYS="$(mktemp -t rv_gkeys.XXXXXX)"
GRANT_AFTER="$(mktemp -t rv_gafter.XXXXXX)"
trap 'rm -f "$PEM" "$CHAIN_FILE" "$LIVE_PEM" "$KEYS_FILE" "$ENV_FILE" "$ENV_TAMPERED" "$RETIRED_KEYS" "$GRANT_PEM" "$GRANT_KEYS" "$GRANT_AFTER"' EXIT

echo
echo "== cr.exec.v1/v2 grant vectors (verify-grant.js == verify_grant.py) =="
if [ ! -f "$GRANT_VECTORS" ]; then
  echo "FAIL  $GRANT_VECTORS missing — run: node test/gen-grant-vectors.js"
  fails=$((fails + 1))
else
  node -e "process.stdout.write(require('./$GRANT_VECTORS').public_key_pem)" > "$GRANT_PEM"
  GRANT_KID="$(node -e "process.stdout.write(require('./$GRANT_VECTORS').kid)")"
  node -e "process.stdout.write(JSON.stringify(require('./$GRANT_VECTORS').registry))" > "$GRANT_KEYS"
  gn="$(node -e "process.stdout.write(String(require('./$GRANT_VECTORS').vectors.length))")"
  for i in $(seq 0 $((gn - 1))); do
    name="$(node -e "process.stdout.write(require('./$GRANT_VECTORS').vectors[$i].name)")"
    token="$(node -e "process.stdout.write(require('./$GRANT_VECTORS').vectors[$i].token)")"
    ev="$(node -e "process.stdout.write(String(require('./$GRANT_VECTORS').vectors[$i].expected.valid))")"
    er="$(node -e "const r=require('./$GRANT_VECTORS').vectors[$i].expected.reason; process.stdout.write(r||'')")"
    es="$(node -e "process.stdout.write(require('./$GRANT_VECTORS').vectors[$i].expected.status||'')")"
    keys_mode="$(node -e "process.stdout.write(require('./$GRANT_VECTORS').vectors[$i].keys||'')")"
    checks=$((checks + 1))

    extra=()
    if [ "$keys_mode" = "retired_registry" ]; then
      node -e "process.stdout.write(JSON.stringify(require('./$GRANT_VECTORS').retired_registry))" > "$GRANT_KEYS"
      extra=(--keys "$GRANT_KEYS")
    else
      node -e "process.stdout.write(JSON.stringify(require('./$GRANT_VECTORS').registry))" > "$GRANT_KEYS"
      extra=(--key "$GRANT_PEM" --kid "$GRANT_KID")
    fi
    op="$(node -e "const f=require('./$GRANT_VECTORS').vectors[$i].flags||{}; process.stdout.write(f['intended-operation']||'')")"
    tgt="$(node -e "const f=require('./$GRANT_VECTORS').vectors[$i].flags||{}; process.stdout.write(f['intended-target']||'')")"
    aud="$(node -e "const f=require('./$GRANT_VECTORS').vectors[$i].flags||{}; process.stdout.write(f['intended-audience']||'')")"
    rec="$(node -e "const f=require('./$GRANT_VECTORS').vectors[$i].flags||{}; process.stdout.write(f.receipt||'')")"
    after="$(node -e "const f=require('./$GRANT_VECTORS').vectors[$i].flags||{}; process.stdout.write(f.after_payload==null?'':String(f.after_payload))")"
    execid="$(node -e "const f=require('./$GRANT_VECTORS').vectors[$i].flags||{}; process.stdout.write(f['intended-executor']||'')")"
    adp="$(node -e "const f=require('./$GRANT_VECTORS').vectors[$i].flags||{}; process.stdout.write(f['intended-adapter']||'')")"
    [ -n "$op" ] && extra+=(--intended-operation "$op")
    [ -n "$tgt" ] && extra+=(--intended-target "$tgt")
    [ -n "$aud" ] && extra+=(--intended-audience "$aud")
    [ -n "$execid" ] && extra+=(--intended-executor "$execid")
    [ -n "$adp" ] && extra+=(--intended-adapter "$adp")
    [ -n "$rec" ] && extra+=(--receipt "$rec")
    if [ -n "$after" ]; then
      printf '%s' "$after" > "$GRANT_AFTER"
      extra+=(--intended-after-file "$GRANT_AFTER")
    fi

    out_js="$(node verify-grant.js "$token" "${extra[@]}" 2>/dev/null)"; code_js=$?
    out_py="$("$PYTHON" verify_grant.py "$token" "${extra[@]}" 2>/dev/null)"; code_py=$?
    gok=1
    if [ "$out_js" != "$out_py" ]; then
      echo "FAIL  $name: JS/PY OUTPUT DIFFER"
      echo "  js: $out_js"
      echo "  py: $out_py"
      gok=0
    fi
    if [ "$code_js" != "$code_py" ]; then
      echo "FAIL  $name: exit codes differ (js=$code_js py=$code_py)"
      gok=0
    fi
    got_valid="$(jsonfield "$out_js" valid)"
    got_reason="$(jsonfield "$out_js" reason)"
    got_status="$(jsonfield "$out_js" status)"
    [ "$got_valid" = "$ev" ] || { echo "FAIL  $name: valid expected=$ev got=$got_valid"; gok=0; }
    [ "$got_status" = "$es" ] || { echo "FAIL  $name: status expected=$es got=$got_status"; gok=0; }
    if [ -n "$er" ] && [ "$got_reason" != "$er" ]; then
      echo "FAIL  $name: reason expected=$er got=$got_reason"
      gok=0
    fi
    want_code=1; [ "$ev" = "true" ] && want_code=0
    if [ "$code_js" != "$want_code" ]; then
      echo "FAIL  $name: exit code expected=$want_code got=$code_js"
      gok=0
    fi
    if [ "$gok" = "1" ]; then
      echo "ok    $name  (js==py; status=$got_status)"
    else
      fails=$((fails + 1))
    fi
  done

  echo
  echo "== 1109 GRANT-SWAP (EG2-SWAP-A token + EG2-SWAP-B intended) =="
  checks=$((checks + 1))
  swap_tok="$(node -e "process.stdout.write(require('./$GRANT_VECTORS').vectors.find(v=>v.name==='EG2-SWAP-A').token)")"
  node -e "process.stdout.write(JSON.stringify(require('./$GRANT_VECTORS').registry))" > "$GRANT_KEYS"
  extra=(--key "$GRANT_PEM" --kid "$GRANT_KID")
  op="$(node -e "const v=require('./$GRANT_VECTORS').vectors.find(x=>x.name==='EG2-SWAP-B'); process.stdout.write((v.flags||{})['intended-operation']||'')")"
  tgt="$(node -e "const v=require('./$GRANT_VECTORS').vectors.find(x=>x.name==='EG2-SWAP-B'); process.stdout.write((v.flags||{})['intended-target']||'')")"
  aud="$(node -e "const v=require('./$GRANT_VECTORS').vectors.find(x=>x.name==='EG2-SWAP-B'); process.stdout.write((v.flags||{})['intended-audience']||'')")"
  rec="$(node -e "const v=require('./$GRANT_VECTORS').vectors.find(x=>x.name==='EG2-SWAP-B'); process.stdout.write((v.flags||{}).receipt||'')")"
  after="$(node -e "const v=require('./$GRANT_VECTORS').vectors.find(x=>x.name==='EG2-SWAP-B'); process.stdout.write((v.flags||{}).after_payload==null?'':String(v.flags.after_payload))")"
  execid="$(node -e "const v=require('./$GRANT_VECTORS').vectors.find(x=>x.name==='EG2-SWAP-B'); process.stdout.write((v.flags||{})['intended-executor']||'')")"
  adp="$(node -e "const v=require('./$GRANT_VECTORS').vectors.find(x=>x.name==='EG2-SWAP-B'); process.stdout.write((v.flags||{})['intended-adapter']||'')")"
  [ -n "$op" ] && extra+=(--intended-operation "$op")
  [ -n "$tgt" ] && extra+=(--intended-target "$tgt")
  [ -n "$aud" ] && extra+=(--intended-audience "$aud")
  [ -n "$execid" ] && extra+=(--intended-executor "$execid")
  [ -n "$adp" ] && extra+=(--intended-adapter "$adp")
  [ -n "$rec" ] && extra+=(--receipt "$rec")
  if [ -n "$after" ]; then
    printf '%s' "$after" > "$GRANT_AFTER"
    extra+=(--intended-after-file "$GRANT_AFTER")
  fi
  out_js="$(node verify-grant.js "$swap_tok" "${extra[@]}" 2>/dev/null)"; code_js=$?
  out_py="$("$PYTHON" verify_grant.py "$swap_tok" "${extra[@]}" 2>/dev/null)"; code_py=$?
  sok=1
  if [ "$out_js" != "$out_py" ]; then
    echo "FAIL  EG2-SWAP-A-as-B: JS/PY OUTPUT DIFFER"
    echo "  js: $out_js"
    echo "  py: $out_py"
    sok=0
  fi
  [ "$code_js" = "$code_py" ] || { echo "FAIL  EG2-SWAP-A-as-B: exit codes differ (js=$code_js py=$code_py)"; sok=0; }
  [ "$(jsonfield "$out_js" valid)" = "false" ] || { echo "FAIL  EG2-SWAP-A-as-B: valid expected=false got=$(jsonfield "$out_js" valid)"; sok=0; }
  [ "$(jsonfield "$out_js" status)" = "GRANT_UNBOUND" ] || { echo "FAIL  EG2-SWAP-A-as-B: status=$(jsonfield "$out_js" status)"; sok=0; }
  [ "$(jsonfield "$out_js" reason)" = "target_mismatch" ] || { echo "FAIL  EG2-SWAP-A-as-B: reason=$(jsonfield "$out_js" reason)"; sok=0; }
  [ "$code_js" = "1" ] || { echo "FAIL  EG2-SWAP-A-as-B: exit expected=1 got=$code_js"; sok=0; }
  if [ "$sok" = "1" ]; then
    echo "ok    EG2-SWAP-A-as-B  (js==py; GRANT_UNBOUND/target_mismatch)"
  else
    fails=$((fails + 1))
  fi
fi

echo
echo "== verify-bundle.test.js (GRANT-SWAP composition) =="
checks=$((checks + 1))
if node --test test/verify-bundle.test.js; then
  echo "ok    verify-bundle.test.js"
else
  echo "FAIL  verify-bundle.test.js"
  fails=$((fails + 1))
fi

echo
echo "== require-grant-smoke + test_grant.py + app-kernel cross-check =="
checks=$((checks + 1))
if node test/require-grant-smoke.js; then
  echo "ok    require-grant-smoke"
else
  echo "FAIL  require-grant-smoke"
  fails=$((fails + 1))
fi
checks=$((checks + 1))
if "$PYTHON" test/test_grant.py; then
  echo "ok    test_grant.py"
else
  echo "FAIL  test_grant.py"
  fails=$((fails + 1))
fi
checks=$((checks + 1))
if node test/cross-check-grant.js; then
  echo "ok    cross-check-grant (js == app kernel on EG-*)"
else
  echo "FAIL  cross-check-grant"
  fails=$((fails + 1))
fi

ATTEST_VECTORS="test/attest-vectors.json"
ATTEST_KEYS="$(mktemp -t rv_akeys.XXXXXX)"
trap 'rm -f "$PEM" "$CHAIN_FILE" "$LIVE_PEM" "$KEYS_FILE" "$ENV_FILE" "$ENV_TAMPERED" "$RETIRED_KEYS" "$GRANT_PEM" "$GRANT_KEYS" "$GRANT_AFTER" "$ATTEST_KEYS"' EXIT

echo
echo "== cr.exec.attest.v1 vectors (verify-attest.js == verify_attest.py) =="
if [ ! -f "$ATTEST_VECTORS" ]; then
  echo "FAIL  $ATTEST_VECTORS missing — run: node test/gen-attest-vectors.js"
  fails=$((fails + 1))
else
  an="$(node -e "process.stdout.write(String(require('./$ATTEST_VECTORS').vectors.length))")"
  for i in $(seq 0 $((an - 1))); do
    name="$(node -e "process.stdout.write(require('./$ATTEST_VECTORS').vectors[$i].name)")"
    token="$(node -e "process.stdout.write(require('./$ATTEST_VECTORS').vectors[$i].token)")"
    ev="$(node -e "process.stdout.write(String(require('./$ATTEST_VECTORS').vectors[$i].expected.valid))")"
    er="$(node -e "const r=require('./$ATTEST_VECTORS').vectors[$i].expected.reason; process.stdout.write(r||'')")"
    es="$(node -e "process.stdout.write(require('./$ATTEST_VECTORS').vectors[$i].expected.status||'')")"
    keys_mode="$(node -e "process.stdout.write(require('./$ATTEST_VECTORS').vectors[$i].keys||'')")"
    checks=$((checks + 1))

    if [ "$keys_mode" = "retired_registry" ]; then
      node -e "process.stdout.write(JSON.stringify(require('./$ATTEST_VECTORS').retired_registry))" > "$ATTEST_KEYS"
    elif [ "$keys_mode" = "empty" ]; then
      node -e "process.stdout.write(JSON.stringify(require('./$ATTEST_VECTORS').empty_registry))" > "$ATTEST_KEYS"
    else
      node -e "process.stdout.write(JSON.stringify(require('./$ATTEST_VECTORS').registry))" > "$ATTEST_KEYS"
    fi
    extra=(--keys "$ATTEST_KEYS")
    grant="$(node -e "const f=require('./$ATTEST_VECTORS').vectors[$i].flags||{}; process.stdout.write(f.grant||'')")"
    rdigest="$(node -e "const f=require('./$ATTEST_VECTORS').vectors[$i].flags||{}; process.stdout.write(f.receipt_digest||'')")"
    [ -n "$grant" ] && extra+=(--grant "$grant")
    [ -n "$rdigest" ] && extra+=(--receipt-digest "$rdigest")

    out_js="$(node verify-attest.js "$token" "${extra[@]}" 2>/dev/null)"; code_js=$?
    out_py="$("$PYTHON" verify_attest.py "$token" "${extra[@]}" 2>/dev/null)"; code_py=$?
    aok=1
    if [ "$out_js" != "$out_py" ]; then
      echo "FAIL  $name: JS/PY OUTPUT DIFFER"
      echo "  js: $out_js"
      echo "  py: $out_py"
      aok=0
    fi
    if [ "$code_js" != "$code_py" ]; then
      echo "FAIL  $name: exit codes differ (js=$code_js py=$code_py)"
      aok=0
    fi
    got_valid="$(jsonfield "$out_js" valid)"
    got_reason="$(jsonfield "$out_js" reason)"
    got_status="$(jsonfield "$out_js" status)"
    [ "$got_valid" = "$ev" ] || { echo "FAIL  $name: valid expected=$ev got=$got_valid"; aok=0; }
    [ "$got_status" = "$es" ] || { echo "FAIL  $name: status expected=$es got=$got_status"; aok=0; }
    if [ -n "$er" ] && [ "$got_reason" != "$er" ]; then
      echo "FAIL  $name: reason expected=$er got=$got_reason"
      aok=0
    fi
    el="$(node -e "process.stdout.write(require('./$ATTEST_VECTORS').vectors[$i].expected.commit_label||'')")"
    if [ -n "$el" ]; then
      got_label="$(jsonfield "$out_js" commit_label)"
      if [ "$got_label" != "$el" ]; then
        echo "FAIL  $name: commit_label expected=$el got=$got_label"
        aok=0
      fi
      if [ "$el" = "authorized_and_host_reported_committed" ] && [ "$got_label" = "authorized_and_committed" ]; then
        echo "FAIL  $name: host-claimed path must not carry authorized_and_committed"
        aok=0
      fi
    fi
    want_code=1; [ "$ev" = "true" ] && want_code=0
    if [ "$code_js" != "$want_code" ]; then
      echo "FAIL  $name: exit code expected=$want_code got=$code_js"
      aok=0
    fi
    if [ "$aok" = "1" ]; then
      echo "ok    $name  (js==py; status=$got_status)"
    else
      fails=$((fails + 1))
    fi
  done
fi

echo
echo "== require-attest-smoke + test_attest.py + app-kernel cross-check =="
checks=$((checks + 1))
if node --test test/verify-attest.test.js; then
  echo "ok    verify-attest.test.js"
else
  echo "FAIL  verify-attest.test.js"
  fails=$((fails + 1))
fi
checks=$((checks + 1))
if node test/require-attest-smoke.js; then
  echo "ok    require-attest-smoke"
else
  echo "FAIL  require-attest-smoke"
  fails=$((fails + 1))
fi
checks=$((checks + 1))
if "$PYTHON" test/test_attest.py; then
  echo "ok    test_attest.py"
else
  echo "FAIL  test_attest.py"
  fails=$((fails + 1))
fi
checks=$((checks + 1))
if node test/cross-check-attest.js; then
  echo "ok    cross-check-attest (js == app kernel on EG-A-*)"
else
  echo "FAIL  cross-check-attest"
  fails=$((fails + 1))
fi

echo
echo "== cr.toolset.attest.v1 vectors (verify-toolset.js == verify_toolset.py) =="
TS_VECTORS="test/toolset-vectors.json"
if [ ! -f "$TS_VECTORS" ]; then
  echo "FAIL  $TS_VECTORS missing"
  fails=$((fails + 1))
else
  TS_KEYS="$(mktemp -t rv_tskeys.XXXXXX)"
  TS_ENT="$(mktemp -t rv_tsent.XXXXXX)"
  node -e "process.stdout.write(JSON.stringify(require('./$TS_VECTORS').registry))" > "$TS_KEYS"
  node -e "process.stdout.write(JSON.stringify(require('./$TS_VECTORS').entries))" > "$TS_ENT"
  tn="$(node -e "process.stdout.write(String(require('./$TS_VECTORS').vectors.length))")"
  for i in $(seq 0 $((tn - 1))); do
    id="$(node -e "process.stdout.write(require('./$TS_VECTORS').vectors[$i].id)")"
    token="$(node -e "process.stdout.write(require('./$TS_VECTORS').vectors[$i].token)")"
    es="$(node -e "process.stdout.write(require('./$TS_VECTORS').vectors[$i].expect.status)")"
    ro="$(node -e "const v=require('./$TS_VECTORS').vectors[$i]; process.stdout.write(v.registry_override?JSON.stringify(v.registry_override):'')")"
    eo="$(node -e "const v=require('./$TS_VECTORS').vectors[$i]; process.stdout.write(v.entries_override?JSON.stringify(v.entries_override):'')")"
    checks=$((checks + 1))

    K="$TS_KEYS"
    if [ -n "$ro" ]; then K="$(mktemp -t rv_tsko.XXXXXX)"; printf '%s' "$ro" > "$K"; fi
    extra=(--keys "$K")
    if [ -n "$eo" ]; then
      E="$(mktemp -t rv_tseo.XXXXXX)"; printf '%s' "$eo" > "$E"; extra+=(--entries "$E")
    elif [ "$id" = "TS-A-VALID" ]; then
      extra+=(--entries "$TS_ENT")
    fi

    out_js="$(node verify-toolset.js "$token" "${extra[@]}" 2>/dev/null)"; code_js=$?
    out_py="$("$PYTHON" verify_toolset.py "$token" "${extra[@]}" 2>/dev/null)"; code_py=$?
    tok_ok=1
    if [ "$out_js" != "$out_py" ]; then
      echo "FAIL  $id: JS/PY OUTPUT DIFFER"
      echo "  js: $out_js"
      echo "  py: $out_py"
      tok_ok=0
    fi
    if [ "$code_js" != "$code_py" ]; then
      echo "FAIL  $id: exit codes differ (js=$code_js py=$code_py)"
      tok_ok=0
    fi
    got="$(printf '%s' "$out_js" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{try{process.stdout.write(JSON.parse(s).status)}catch(e){process.stdout.write('PARSE_ERROR')}})")"
    if [ "$got" != "$es" ]; then
      echo "FAIL  $id: status $got != expected $es"
      tok_ok=0
    fi
    if [ "$tok_ok" = "1" ]; then echo "ok    $id  js=py=$es"; else fails=$((fails + 1)); fi
  done
  rm -f "$TS_KEYS" "$TS_ENT"
fi
checks=$((checks + 1))
# 1127 — the harness prints its own verdict line INCLUDING which kernel it compared against
# ([LIVE] or [RECORDED]). This wrapper used to print a fixed "js == app kernel" line regardless,
# which is how a comparison against a recording would read as the live one.
if node test/cross-check-toolset.js; then
  :
else
  echo "FAIL  cross-check-toolset"
  fails=$((fails + 1))
fi


MON_VECTORS="test/monitor-vectors.json"
echo
echo "== cr.monitor.attest.v1 vectors (verify-monitor.js == verify_monitor.py) =="
if [ ! -f "$MON_VECTORS" ]; then
  echo "FAIL  $MON_VECTORS missing — run: node test/gen-monitor-vectors.js"
  fails=$((fails + 1))
else
  MON_KEYS="$(mktemp -t rv_mkeys.XXXXXX)"
  mn="$(node -e "process.stdout.write(String(require('./$MON_VECTORS').vectors.length))")"
  for i in $(seq 0 $((mn - 1))); do
    name="$(node -e "process.stdout.write(require('./$MON_VECTORS').vectors[$i].name)")"
    token="$(node -e "process.stdout.write(require('./$MON_VECTORS').vectors[$i].token)")"
    ev="$(node -e "process.stdout.write(String(require('./$MON_VECTORS').vectors[$i].expected.valid))")"
    er="$(node -e "const r=require('./$MON_VECTORS').vectors[$i].expected.reason; process.stdout.write(r||'')")"
    es="$(node -e "process.stdout.write(require('./$MON_VECTORS').vectors[$i].expected.status||'')")"
    keys_mode="$(node -e "process.stdout.write(require('./$MON_VECTORS').vectors[$i].keys||'')")"
    checks=$((checks + 1))

    if [ "$keys_mode" = "retired_registry" ]; then
      node -e "process.stdout.write(JSON.stringify(require('./$MON_VECTORS').retired_registry))" > "$MON_KEYS"
    elif [ "$keys_mode" = "empty" ]; then
      node -e "process.stdout.write(JSON.stringify(require('./$MON_VECTORS').empty_registry))" > "$MON_KEYS"
    else
      node -e "process.stdout.write(JSON.stringify(require('./$MON_VECTORS').registry))" > "$MON_KEYS"
    fi
    extra=(--keys "$MON_KEYS")
    did="$(node -e "const f=require('./$MON_VECTORS').vectors[$i].flags||{}; process.stdout.write(f.decision_id||'')")"
    rdigest="$(node -e "const f=require('./$MON_VECTORS').vectors[$i].flags||{}; process.stdout.write(f.receipt_digest||'')")"
    [ -n "$did" ] && extra+=(--decision-id "$did")
    [ -n "$rdigest" ] && extra+=(--receipt-digest "$rdigest")

    out_js="$(node verify-monitor.js "$token" "${extra[@]}" 2>/dev/null)"; code_js=$?
    out_py="$("$PYTHON" verify_monitor.py "$token" "${extra[@]}" 2>/dev/null)"; code_py=$?
    mok=1
    if [ "$out_js" != "$out_py" ]; then
      echo "FAIL  $name: JS/PY OUTPUT DIFFER"
      echo "  js: $out_js"
      echo "  py: $out_py"
      mok=0
    fi
    if [ "$code_js" != "$code_py" ]; then
      echo "FAIL  $name: exit codes differ (js=$code_js py=$code_py)"
      mok=0
    fi
    got_valid="$(jsonfield "$out_js" valid)"
    got_reason="$(jsonfield "$out_js" reason)"
    got_status="$(jsonfield "$out_js" status)"
    [ "$got_valid" = "$ev" ] || { echo "FAIL  $name: valid expected=$ev got=$got_valid"; mok=0; }
    [ "$got_status" = "$es" ] || { echo "FAIL  $name: status expected=$es got=$got_status"; mok=0; }
    if [ -n "$er" ] && [ "$got_reason" != "$er" ]; then
      echo "FAIL  $name: reason expected=$er got=$got_reason"
      mok=0
    fi
    want_code=1; [ "$ev" = "true" ] && want_code=0
    if [ "$code_js" != "$want_code" ]; then
      echo "FAIL  $name: exit code expected=$want_code got=$code_js"
      mok=0
    fi
    if [ "$mok" = "1" ]; then
      echo "ok    $name  (js==py; status=$got_status)"
    else
      fails=$((fails + 1))
    fi
  done
  rm -f "$MON_KEYS"
fi
checks=$((checks + 1))
if node test/cross-check-monitor.js; then
  echo "ok    cross-check-monitor (js == app kernel on MON-A-*)"
else
  echo "FAIL  cross-check-monitor"
  fails=$((fails + 1))
fi
echo
echo "checks=$checks fails=$fails"
[ "$fails" = "0" ] && { echo "ALL PASS"; exit 0; } || { echo "FAILURES: $fails"; exit 1; }
