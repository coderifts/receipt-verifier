"""
schema_validate: a tiny, dependency-free validator for the attestation bundle.

It reads bundle.schema.json (the canonical reference) and enforces the subset of
JSON Schema that schema uses: type, required, additionalProperties=false, enum,
pattern, minLength, and minimum. This keeps bundle.schema.json the single source
of truth while staying pure stdlib, so a conformance check needs no installs.

    errors = validate_bundle_schema(bundle)   # [] means valid
"""

import json
import os
import re

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bundle.schema.json")

_TYPE = {"object": dict, "string": str, "integer": int}


def load_schema(path=SCHEMA_PATH):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _check_field(name, value, spec):
    errs = []
    t = spec.get("type")
    if t == "integer" and isinstance(value, bool):
        return ["%s: expected integer, got boolean" % name]
    if t and not isinstance(value, _TYPE[t]):
        return ["%s: expected %s, got %s" % (name, t, type(value).__name__)]
    if "enum" in spec and value not in spec["enum"]:
        errs.append("%s: %r not in %s" % (name, value, spec["enum"]))
    if "pattern" in spec and isinstance(value, str) and not re.search(spec["pattern"], value):
        errs.append("%s: %r does not match %s" % (name, value, spec["pattern"]))
    if "minLength" in spec and isinstance(value, str) and len(value) < spec["minLength"]:
        errs.append("%s: shorter than minLength %d" % (name, spec["minLength"]))
    if "minimum" in spec and isinstance(value, int) and value < spec["minimum"]:
        errs.append("%s: %s below minimum %s" % (name, value, spec["minimum"]))
    return errs


def validate_bundle_schema(bundle, schema=None):
    schema = schema or load_schema()
    errors = []
    if not isinstance(bundle, dict):
        return ["bundle: expected object"]
    for req in schema.get("required", []):
        if req not in bundle:
            errors.append("missing required field: %s" % req)
    props = schema.get("properties", {})
    if schema.get("additionalProperties") is False:
        for k in bundle:
            if k not in props:
                errors.append("unexpected field: %s" % k)
    for name, value in bundle.items():
        if name in props:
            errors.extend(_check_field(name, value, props[name]))
    return errors
