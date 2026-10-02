from __future__ import annotations

import argparse
import bisect
import csv
import html
import hashlib
import json
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGN = ROOT / "data" / "results" / "afl_nas_seed_comparison"
PARSERS = ("gmm", "gsm")
MAX_INPUT_BYTES = 4096
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")
HEX_RE = re.compile(r"^[0-9a-fA-F\s]+$")

# Compact, protocol-shaped and malformed NAS PDU examples for the conventional arm.
ORDINARY_SEEDS = {
    "gmm": (
        "7e0043",
        "7e005e",
        "7e005d18",
        "7e005b",
        "7e0000",
        "7e01",
        "7e",
        "7e00",
    ),
    "gsm": (
        "2e0100",
        "2e010d",
        "2e010a",
        "2e020d00",
        "2e0000",
        "2e01",
        "2e",
        "2e00",
    ),
}

# Structured, grammar/builder-assisted seed generation (Phase 1). Instead of
# asking a model for whole-message hex, we ask it for a short JSON spec naming
# real free5gc/nas IEs and value octets; a Go program (nas_seed_compiler)
# builds the message with the authoritative message.RegReq / PDUSessEstReq
# structs and only then applies any requested malformation. This keeps
# protocol framing (header, TLV length bytes, IEI order) correct by
# construction unless a mutation deliberately breaks it.
ARCHETYPES = ("deep_valid", "tlv_boundary", "ie_sequencing", "truncated")
MESSAGE_TYPE_BY_PARSER = {
    "gmm": "registration_request",
    "gsm": "pdu_session_establishment_request",
}
# IEs the compiler can locate and mutate, by message type. Keep in sync with
# the `table`/`tlvTable` entries in harness/nas_seed_compiler/main.go. Limited
# to IEs that are present by default (i.e. a model does not also need to
# remember to set a field to include them) so mutation targeting is a single
# decision, not two coordinated ones a small model can get out of sync.
MUTABLE_IES = {
    "registration_request": {
        "capability_5gmm",
        "ue_security_capability",
        "requested_nssai",
    },
    "pdu_session_establishment_request": {"capability_5gsm", "extended_pco"},
}
MUTATION_OPS = {"truncate", "set_ie_length", "duplicate_ie", "move_ie_to_front"}
# Extended Protocol Discriminator, 3GPP TS 24.501 clause 9.2: every valid NAS
# PDU for a given parser must start with this byte.
EPD_BY_PARSER = {"gmm": 0x7E, "gsm": 0x2E}
MIN_SEED_BYTES = 4
CURATED_SEED_SUITE_PATH = ROOT / "data" / "raw" / "nas_seed_suite_20261002" / "seeds.json"
CURATED_CATEGORY_TO_ARCHETYPE = {
    "CATEGORY_VALID_DEEP": "deep_valid",
    "CATEGORY_BOUNDARY_TLV": "tlv_boundary",
    "CATEGORY_IE_PERMUTATION": "ie_sequencing",
    "CATEGORY_TRUNCATED_BOUNDS": "truncated",
}

STAT_MAP = {
    "run_time": "runtime_seconds",
    "execs_done": "executions",
    "execs_per_sec": "executions_per_second",
    "corpus_count": "final_corpus",
    "corpus_found": "corpus_found",
    "max_depth": "maximum_depth",
    "bitmap_cvg": "bitmap_coverage",
    "edges_found": "edges_found",
    "total_edges": "total_edges",
    "saved_crashes": "saved_crashes",
    "saved_hangs": "saved_hangs",
    "total_tmout": "timeouts",
    "stability": "stability",
}


def model_slug(model: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", model).strip("_").lower()
    if not slug:
        raise ValueError(f"invalid model name: {model!r}")
    return slug


def build_paired_run_plan(models: list[str], repeats: int, base_seed: int) -> list[dict[str, Any]]:
    """Create a reproducible, balanced sequence of paired arm runs."""
    if len(models) < 2 or len({model_slug(model) for model in models}) != len(models):
        raise ValueError("provide at least two distinct model names")
    if repeats < 2:
        raise ValueError("use at least two repetitions for a repeated pilot")
    pairs = [
        {"model": model, "parser": parser_name, "repeat": repeat, "afl_seed": base_seed + repeat}
        for repeat in range(1, repeats + 1)
        for model in models
        for parser_name in PARSERS
    ]
    random.Random(base_seed).shuffle(pairs)
    plan = []
    for pair in pairs:
        arms = ["ordinary", "llm"]
        if pair["repeat"] % 2 == 0:
            arms.reverse()
        plan.extend({**pair, "arm": arm} for arm in arms)
    return plan


def apply_seed_hygiene(
    seeds: list[bytes], parser_name: str, hand_crafted_hashes: set[str]
) -> tuple[list[bytes], dict[str, Any]]:
    """Pre-fuzzing hygiene filter (Phase 1.3): reject too-short seeds and
    seeds with the wrong Extended Protocol Discriminator, deduplicate by
    SHA-256, and report cross-arm overlap against the hand-crafted suite.
    Never silently drops information: every rejection is counted and
    returned, not just discarded.
    """
    expected_epd = EPD_BY_PARSER[parser_name]
    kept: list[bytes] = []
    seen: set[str] = set()
    rejected_too_short = 0
    rejected_bad_discriminator = 0
    rejected_duplicate = 0
    for seed in seeds:
        digest = hashlib.sha256(seed).hexdigest()
        if len(seed) < MIN_SEED_BYTES:
            rejected_too_short += 1
            continue
        if seed[0] != expected_epd:
            rejected_bad_discriminator += 1
            continue
        if digest in seen:
            rejected_duplicate += 1
            continue
        seen.add(digest)
        kept.append(seed)
    overlap_count = len(seen & hand_crafted_hashes)
    report = {
        "input_count": len(seeds),
        "kept_count": len(kept),
        "rejected_too_short": rejected_too_short,
        "rejected_bad_discriminator": rejected_bad_discriminator,
        "rejected_duplicate": rejected_duplicate,
        "cross_arm_overlap_with_handcrafted_count": overlap_count,
        "cross_arm_overlap_with_handcrafted_percent": (
            round(100.0 * overlap_count / len(kept), 2) if kept else 0.0
        ),
    }
    return kept, report


def _load_curated_seeds_by_archetype(parser_name: str) -> dict[str, list[bytes]]:
    """Group the hand-crafted 16-seed suite by archetype for a given parser,
    so the ordinary arm can be matched archetype-for-archetype against the
    LLM-structured arm instead of comparing against trivial 2-3 byte stubs.
    """
    entries = json.loads(CURATED_SEED_SUITE_PATH.read_text(encoding="utf-8"))
    by_archetype: dict[str, list[bytes]] = {name: [] for name in ARCHETYPES}
    for entry in entries:
        if entry["protocol"].lower() != parser_name:
            continue
        archetype = CURATED_CATEGORY_TO_ARCHETYPE[entry["category"]]
        by_archetype[archetype].append(bytes.fromhex(entry["hex"]))
    return by_archetype


def curated_ordinary_seeds(parser_name: str, count: int) -> list[bytes]:
    """Pick `count` hand-crafted seeds for parser_name, spread evenly across
    the four archetypes so the ordinary arm is archetype-matched against the
    structured LLM arm rather than being systematically shallower.
    """
    if count % len(ARCHETYPES) != 0:
        raise ValueError(f"structured strategy requires count to be a multiple of {len(ARCHETYPES)}")
    per_archetype = count // len(ARCHETYPES)
    by_archetype = _load_curated_seeds_by_archetype(parser_name)
    seeds: list[bytes] = []
    for archetype in ARCHETYPES:
        available = by_archetype[archetype]
        if len(available) < per_archetype:
            raise ValueError(
                f"curated suite only has {len(available)} {parser_name.upper()} seeds for "
                f"archetype {archetype}; need {per_archetype}"
            )
        seeds.extend(available[:per_archetype])
    return seeds


def _structured_spec_prompt(parser_name: str, archetype: str, count: int) -> str:
    message_type = MESSAGE_TYPE_BY_PARSER[parser_name]
    mutable_ies = sorted(MUTABLE_IES[message_type])
    if message_type == "registration_request":
        field_doc = (
            'Fields for "registration_request": registration_type (uint8), '
            "security_capability_hex (2-8 byte hex, omit/empty to drop the IE; this field builds "
            'the "ue_security_capability" IE), '
            "capability_5gmm_hex (1-13 byte hex, omit/empty to drop; this field builds the "
            '"capability_5gmm" IE), '
            'nssai (list of {"sst": uint8, "sd_hex": 3-byte hex}, [] to drop; builds the '
            '"requested_nssai" IE). Do not set mobile_identity_hex or uplink_data_status_hex; '
            "those use fixed safe defaults."
        )
        example_fields = (
            '{"registration_type":1,'
            '"security_capability_hex":"8080","capability_5gmm_hex":"80",'
            '"nssai":[{"sst":1,"sd_hex":"010203"}]}'
        )
    else:
        field_doc = (
            'Fields for "pdu_session_establishment_request": pdu_session_id (uint8), '
            "pti (uint8), integrity_uplink (uint8), integrity_downlink (uint8), "
            'pdu_session_type ("ipv4"|"ipv6"|"ipv4v6"|"unstructured"|"ethernet", omit to drop), '
            "ssc_mode (1|2|3, omit to drop), "
            'capability_5gsm_hex (hex string, omit/empty to drop; this field builds the '
            '"capability_5gsm" IE), '
            'include_extended_pco (bool; this field builds the "extended_pco" IE), '
            "extended_pco_dns_v4 (bool), extended_pco_dns_v6 (bool)."
        )
        example_fields = (
            '{"pdu_session_id":1,"pti":0,"integrity_uplink":255,"integrity_downlink":255,'
            '"pdu_session_type":"ipv4","ssc_mode":1,"capability_5gsm_hex":"02"}'
        )
    archetype_doc = {
        "deep_valid": (
            "deep_valid: include every mandatory and optional IE above (full mandatory + "
            'optional coverage). The "mutations" list MUST be exactly []: do not add any '
            "mutation for this archetype. Vary the field values across specs."
        ),
        "tlv_boundary": (
            "tlv_boundary: build a normal message, then add ONE mutation of the form "
            '{"op": "set_ie_length", "ie": <IE name>, "declared_length": N}, with N=0, N=255 '
            "(or the IE's max length+1), or a length that mismatches the real payload size. "
            f"Valid IE names: {mutable_ies}."
        ),
        "ie_sequencing": (
            "ie_sequencing: build a normal message, then add ONE mutation of the form "
            '{"op": "duplicate_ie", "ie": <IE name>} or {"op": "move_ie_to_front", "ie": <IE name>}. '
            f"Valid IE names: {mutable_ies}."
        ),
        "truncated": (
            "truncated: build a normal message, then add ONE mutation of the form "
            '{"op": "truncate", "after_bytes": N}, where N is small enough to cut off in the '
            "middle of an IE value."
        ),
    }[archetype]
    spec_shape = (
        '{"specs": [{"parser": "' + parser_name + '", "message_type": "' + message_type
        + '", "archetype": "' + archetype + '", "fields": {...}, "mutations": [...]}, ...]}'
    )
    return (
        f"You are generating {count} structured test specs for the free5gc/nas "
        f'"{message_type}" {parser_name.upper()} parser, archetype "{archetype}". '
        f"Do not emit whole-message hex. Emit ONLY a JSON object shaped like {spec_shape}. "
        f"{field_doc} {archetype_doc} "
        f'IMPORTANT: "mutations[].ie" must be one of the IE names {mutable_ies} (not a field key '
        f"from fields above). Only use mutation ops from {sorted(MUTATION_OPS)}. "
        f"Example fields object: {example_fields}. "
        f"Return exactly {count} specs, each internally consistent and distinct. Output JSON only."
    )


# Field key that must build each mutable IE, used to force the IE present
# whenever a mutation targets it (a small model will sometimes ask to mutate
# an IE while also, inconsistently, omitting/emptying the field that builds
# it; rather than burn retries hoping it self-corrects, we enforce the one
# invariant mutation targeting actually requires: the IE must exist).
FIELD_KEY_FOR_MUTABLE_IE = {
    "registration_request": {
        "capability_5gmm": "capability_5gmm_hex",
        "ue_security_capability": "security_capability_hex",
        "requested_nssai": "nssai",
    },
    "pdu_session_establishment_request": {
        "capability_5gsm": "capability_5gsm_hex",
        "extended_pco": "include_extended_pco",
    },
}


# Byte-length constraints (per the free5gc/nas IE comments) and a safe
# default for each model-overridable hex field. Models occasionally pick
# invalid lengths (e.g. odd-length UESecCapability, which must be 2-8 even
# bytes); rather than burn retries, fall back to the default deterministically.
HEX_FIELD_CONSTRAINTS = {
    "registration_request": {
        "security_capability_hex": (2, 8, True, "8080"),
        "capability_5gmm_hex": (1, 13, False, "80"),
    },
    "pdu_session_establishment_request": {
        "capability_5gsm_hex": (1, 13, False, "02"),
    },
}


def _sanitize_hex_fields(fields: dict[str, Any], message_type: str) -> None:
    for key, (min_bytes, max_bytes, must_be_even, default) in HEX_FIELD_CONSTRAINTS[message_type].items():
        value = fields.get(key)
        if value is None or value == "":
            continue
        try:
            length = len(bytes.fromhex(value))
        except (ValueError, TypeError):
            length = -1
        if length < min_bytes or length > max_bytes or (must_be_even and length % 2):
            fields[key] = default
    if message_type == "registration_request" and isinstance(fields.get("nssai"), list):
        for entry in fields["nssai"]:
            if not isinstance(entry, dict):
                continue
            sd_hex = entry.get("sd_hex")
            try:
                valid = sd_hex is not None and len(bytes.fromhex(sd_hex)) == 3
            except (ValueError, TypeError):
                valid = False
            if not valid:
                entry["sd_hex"] = "010203"


def _validate_structured_spec(spec: Any, parser_name: str, archetype: str) -> dict[str, Any]:
    """Fail-closed shape check before spending a compiler call: reject specs
    that target the wrong parser/archetype/message type, or reference a
    mutation op/IE outside the supported whitelist.
    """
    if not isinstance(spec, dict):
        raise ValueError("spec is not a JSON object")
    message_type = MESSAGE_TYPE_BY_PARSER[parser_name]
    if spec.get("parser") != parser_name:
        raise ValueError(f"spec parser {spec.get('parser')!r} != {parser_name!r}")
    if spec.get("message_type") != message_type:
        raise ValueError(f"spec message_type {spec.get('message_type')!r} != {message_type!r}")
    if spec.get("archetype") != archetype:
        raise ValueError(f"spec archetype {spec.get('archetype')!r} != {archetype!r}")
    fields = spec.get("fields", {})
    if not isinstance(fields, dict):
        raise ValueError("spec.fields is not a JSON object")
    fields = dict(fields)
    # Not core to any archetype's test intent, and small models frequently
    # supply invalid encodings (wrong MobileId5GS sub-type, too-short Psi);
    # always use the compiler's safe defaults instead of trusting the model.
    fields.pop("mobile_identity_hex", None)
    fields.pop("uplink_data_status_hex", None)
    fields.pop("nas_message_container_hex", None)
    _sanitize_hex_fields(fields, message_type)
    mutations = spec.get("mutations", [])
    if not isinstance(mutations, list):
        raise ValueError("spec.mutations is not a JSON array")
    if archetype == "deep_valid":
        # deep_valid is defined as "no deliberate malformation"; small models
        # sometimes add a mutation anyway despite instructions. Enforce the
        # archetype's definition here rather than relying on model
        # compliance, but never hide that it happened.
        mutations = []
    else:
        # Every malformation archetype is defined as exactly one mutation.
        # Small models often add several anyway (e.g. corrupting every IE's
        # length for tlv_boundary); the compiler also only tracks IE spans up
        # to the first buffer-reshaping mutation (duplicate_ie/
        # move_ie_to_front invalidate offsets), so later mutations cannot be
        # reasoned about safely regardless of intent. Deterministically keep
        # only the model's first mutation rather than reject and retry.
        mutations = mutations[:1]
        # Drop any field override that would disable an IE a mutation
        # targets, so the field falls back to its (present-by-default) value.
        field_overrides = FIELD_KEY_FOR_MUTABLE_IE[message_type]
        for mutation in mutations:
            if isinstance(mutation, dict) and mutation.get("ie") in field_overrides:
                fields.pop(field_overrides[mutation["ie"]], None)
    for mutation in mutations:
        if not isinstance(mutation, dict) or mutation.get("op") not in MUTATION_OPS:
            raise ValueError(f"unsupported mutation op in {mutation!r}")
        ie_name = mutation.get("ie")
        if ie_name is not None and ie_name not in MUTABLE_IES[message_type]:
            raise ValueError(f"unsupported mutation IE {ie_name!r} for {message_type}")
        if mutation.get("op") == "truncate":
            # Models frequently pick after_bytes below the hygiene floor
            # (e.g. 2-3 bytes). Clamp deterministically rather than reject:
            # the archetype's intent (cut off mid-IE) still holds at the
            # floor, since the mandatory header alone already exceeds it.
            after_bytes = mutation.get("after_bytes")
            if isinstance(after_bytes, int) and after_bytes < MIN_SEED_BYTES:
                mutation["after_bytes"] = MIN_SEED_BYTES
        elif mutation.get("op") == "set_ie_length":
            # Models sometimes omit declared_length entirely. Default to 255
            # (the max-length-overflow case tlv_boundary is meant to probe)
            # rather than failing a spec that is otherwise well-formed.
            if not isinstance(mutation.get("declared_length"), int):
                mutation["declared_length"] = 255
    return {"parser": parser_name, "message_type": message_type, "archetype": archetype,
            "fields": fields, "mutations": mutations}


def _build_seed_compiler(campaign: Path, go: Path | None = None) -> Path:
    go_binary = go or (Path.home() / "opt" / "go" / "bin" / "go")
    test_module = ROOT / "vendor" / "free5gc" / "test"
    compiler_source = ROOT / "harness" / "nas_seed_compiler" / "main.go"
    if not go_binary.is_file():
        raise FileNotFoundError(f"Go executable not found: {go_binary}")
    target_dir = campaign / "artifacts"
    target_dir.mkdir(parents=True, exist_ok=True)
    binary = target_dir / "nas-seed-compiler"
    env = os.environ.copy()
    env["GOROOT"] = str(go_binary.parent.parent)
    env["PATH"] = str(go_binary.parent) + os.pathsep + env.get("PATH", "")
    subprocess.run(
        [str(go_binary), "build", "-trimpath", "-o", str(binary), str(compiler_source)],
        cwd=test_module,
        env=env,
        check=True,
    )
    return binary


def _compile_specs(compiler_binary: Path, specs: list[dict[str, Any]]) -> list[tuple[bytes | None, str]]:
    """Run validated specs through the Go compiler in one batch (JSON Lines
    in, JSON Lines out) and return (seed_bytes_or_None, error_message) pairs
    in the same order, never silently dropping a failed spec.
    """
    if not specs:
        return []
    stdin_text = "\n".join(json.dumps(spec) for spec in specs) + "\n"
    result = subprocess.run(
        [str(compiler_binary)], input=stdin_text, capture_output=True, text=True, check=True
    )
    lines = result.stdout.strip("\n").split("\n")
    if len(lines) != len(specs):
        raise RuntimeError(f"compiler returned {len(lines)} results for {len(specs)} specs")
    outcomes: list[tuple[bytes | None, str]] = []
    for line in lines:
        payload = json.loads(line)
        if payload.get("error"):
            outcomes.append((None, payload["error"]))
        else:
            outcomes.append((bytes.fromhex(payload["hex"]), ""))
    return outcomes


def _generate_structured_model_seeds(
    model: str,
    parser_name: str,
    count: int,
    base_url: str,
    compiler_binary: Path,
    hand_crafted_hashes: set[str],
) -> tuple[list[bytes], dict[str, Any]]:
    """Grammar/builder-assisted seed generation (Phase 1.1/1.2): request
    archetype-partitioned structured specs from the model, validate and
    compile them deterministically, then apply the hygiene filter (1.3).
    """
    if count % len(ARCHETYPES) != 0:
        raise ValueError(f"structured strategy requires count to be a multiple of {len(ARCHETYPES)}")
    per_archetype = count // len(ARCHETYPES)
    generated: list[bytes] = []
    seen_hashes: set[str] = set()
    compile_errors: list[str] = []
    for archetype in ARCHETYPES:
        accepted_for_archetype = 0
        for _attempt in range(6):
            needed = per_archetype - accepted_for_archetype
            if needed <= 0:
                break
            text = _request_ollama_structured(model, base_url, parser_name, archetype, needed)
            try:
                raw_specs = json.loads(text)
                if isinstance(raw_specs, dict):
                    raw_specs = raw_specs.get("specs", [])
                if not isinstance(raw_specs, list):
                    raise ValueError("expected a JSON array of specs")
            except (json.JSONDecodeError, ValueError) as exc:
                compile_errors.append(f"{archetype}: could not parse model output as spec array: {exc}")
                continue
            validated = []
            for raw_spec in raw_specs:
                try:
                    validated.append(_validate_structured_spec(raw_spec, parser_name, archetype))
                except ValueError as exc:
                    compile_errors.append(f"{archetype}: rejected spec: {exc}")
            for seed, error in _compile_specs(compiler_binary, validated):
                if error:
                    compile_errors.append(f"{archetype}: compiler error: {error}")
                    continue
                if len(seed) < MIN_SEED_BYTES:
                    compile_errors.append(
                        f"{archetype}: compiled seed is {len(seed)} bytes (< {MIN_SEED_BYTES}); rejected by hygiene"
                    )
                    continue
                if seed[0] != EPD_BY_PARSER[parser_name]:
                    compile_errors.append(
                        f"{archetype}: compiled seed has EPD 0x{seed[0]:02x}, expected "
                        f"0x{EPD_BY_PARSER[parser_name]:02x}; rejected by hygiene"
                    )
                    continue
                digest = hashlib.sha256(seed).hexdigest()
                if digest in seen_hashes:
                    continue
                seen_hashes.add(digest)
                generated.append(seed)
                accepted_for_archetype += 1
                if accepted_for_archetype == per_archetype:
                    break
        if accepted_for_archetype != per_archetype:
            raise ValueError(
                f"{model} produced only {accepted_for_archetype}/{per_archetype} valid "
                f"{parser_name.upper()} {archetype} seeds after six requests; "
                f"errors: {compile_errors[-5:]}"
            )
    kept, hygiene_report = apply_seed_hygiene(generated, parser_name, hand_crafted_hashes)
    if len(kept) != count:
        raise ValueError(
            f"{model} produced {len(kept)}/{count} {parser_name.upper()} seeds that passed hygiene "
            f"(EPD/length/dedup); report={hygiene_report}"
        )
    hygiene_report["compile_errors"] = compile_errors
    return kept, hygiene_report


def _generate_unique_model_seeds(model: str, parser_name: str, count: int, base_url: str) -> list[bytes]:
    generated: list[bytes] = []
    for _attempt in range(4):
        needed = count - len(generated)
        if not needed:
            break
        text = _request_ollama(model, base_url, parser_name, needed, [seed.hex() for seed in generated])
        for candidate in _parse_seed_candidates(text):
            if candidate not in generated:
                generated.append(candidate)
            if len(generated) == count:
                break
    if len(generated) != count:
        raise ValueError(f"{model} returned only {len(generated)} unique {parser_name.upper()} seeds")
    return generated


def prepare_model_matrix(
    campaign: Path,
    models: list[str],
    count: int,
    base_url: str,
    base_seed: int,
    repeats: int,
    strategy: str = "structured",
    go_binary: Path | None = None,
) -> None:
    if strategy not in ("structured", "raw_hex"):
        raise ValueError(f"unknown strategy {strategy!r}; use 'structured' or 'raw_hex'")
    if strategy == "raw_hex":
        if count < 2 or count > len(ORDINARY_SEEDS["gmm"]):
            raise ValueError("seed count must be between 2 and 8 for raw_hex")
    elif count % len(ARCHETYPES) != 0:
        raise ValueError(f"structured strategy requires count to be a multiple of {len(ARCHETYPES)}")
    plan = build_paired_run_plan(models, repeats, base_seed)
    manifest_path = campaign / "matrix_manifest.json"
    if campaign.exists() and any(campaign.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty matrix campaign: {campaign}")

    hygiene_reports: dict[str, Any] = {}
    if strategy == "structured":
        campaign.mkdir(parents=True, exist_ok=True)
        compiler_binary = _build_seed_compiler(campaign, go_binary)
        hand_crafted_hashes = {
            hashlib.sha256(bytes.fromhex(entry["hex"])).hexdigest()
            for entry in json.loads(CURATED_SEED_SUITE_PATH.read_text(encoding="utf-8"))
        }
        ordinary_by_parser = {parser_name: curated_ordinary_seeds(parser_name, count) for parser_name in PARSERS}
        generated = {}
        for model in models:
            generated[model] = {}
            for parser_name in PARSERS:
                seeds, report = _generate_structured_model_seeds(
                    model, parser_name, count, base_url, compiler_binary, hand_crafted_hashes
                )
                generated[model][parser_name] = seeds
                hygiene_reports[f"{model_slug(model)}/{parser_name}"] = report
        ordinary_source = "curated_handcrafted_archetype_matched"
    else:
        ordinary_by_parser = {
            parser_name: [bytes.fromhex(value) for value in ORDINARY_SEEDS[parser_name][:count]]
            for parser_name in PARSERS
        }
        generated = {
            model: {
                parser_name: _generate_unique_model_seeds(model, parser_name, count, base_url)
                for parser_name in PARSERS
            }
            for model in models
        }
        ordinary_source = "ordinary_protocol_templates"

    corpus_rows: list[dict[str, Any]] = []
    overlap_by_model_parser: dict[str, int] = {}
    for model in models:
        slug = model_slug(model)
        for parser_name in PARSERS:
            ordinary = ordinary_by_parser[parser_name]
            llm_seeds = generated[model][parser_name]
            overlap_by_model_parser[f"{slug}/{parser_name}"] = len(set(ordinary) & set(llm_seeds))
            model_root = campaign / "corpora" / slug / parser_name
            corpus_rows.extend(_write_corpus(
                model_root / "ordinary", ordinary, parser_name, "ordinary", ordinary_source, None
            ))
            corpus_rows.extend(_write_corpus(
                model_root / "llm", llm_seeds, parser_name, "llm", "ollama_generated", model
            ))

    campaign.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": "afl-multimodel-seed-study-v2",
        "seed_strategy": strategy,
        "models": models,
        "parsers": list(PARSERS),
        "repeats": repeats,
        "seeds_per_arm_per_parser": count,
        "ollama_base_url": base_url,
        "free5gc_commit": _free5gc_commit(),
        "harness_path": str((ROOT / "harness" / "nas_parser" / "main.go").relative_to(ROOT)),
        "harness_sha256": _sha256(ROOT / "harness" / "nas_parser" / "main.go"),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_afl_seed": base_seed,
        "cross_arm_duplicate_inputs": overlap_by_model_parser,
        "ordinary_seed_source": ordinary_source,
        "seed_hygiene_reports": hygiene_reports,
        "run_plan": plan,
        "corpora": corpus_rows,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def run_model_matrix(
    campaign: Path,
    afl: Path,
    runtime: int,
    timeout_ms: int,
    memory_mb: int,
    go_binary: Path | None = None,
    shard_index: int = 0,
    shard_count: int = 1,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    manifest_path = campaign / "matrix_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if runtime < 30 or timeout_ms < 100 or memory_mb < 256:
        raise ValueError("runtime/timeout/memory limits are below the experiment minimum")
    if runtime < 600 or int(manifest.get("repeats", 0)) < 5:
        raise ValueError("Phase 4 matrix requires --runtime >= 600 seconds and at least 5 paired repetitions")
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard index must be in [0, shard_count)")

    selected_go = go_binary or (Path.home() / "opt" / "go" / "bin" / "go")
    env = os.environ.copy()
    env["AFL_PATH"] = str(afl.parent.parent / "lib" / "afl")
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_FUZZER_STATS_UPDATE_INTERVAL"] = "5"
    # Phase 2.1: lock Go runtime determinism (no async-preemption signal jitter,
    # no GC pauses/trace noise, no goroutine scheduling across cores).
    env.update({"GOMAXPROCS": "1", "GOGC": "off", "GODEBUG": "asyncpreemptoff=1,gctrace=0"})
    env["GOROOT"] = str(selected_go.parent.parent)
    env["PATH"] = os.pathsep.join((str(afl.parent), str(selected_go.parent), env.get("PATH", "")))
    binary = _build_target(campaign, selected_go)
    qemu_binary = afl.parent / "afl-qemu-trace"
    code_range = _resolve_nas_code_range(binary)
    if code_range is not None:
        env["AFL_CODE_START"], env["AFL_CODE_END"] = code_range
    run_config = {
        "schema_version": "afl-multimodel-run-v1",
        "free5gc_commit": _free5gc_commit(),
        "harness_sha256": _sha256(ROOT / "harness" / "nas_parser" / "main.go"),
        "binary_path": str(binary),
        "binary_sha256": _sha256(binary),
        "go_version": _tool_output([str(selected_go), "version"], env),
        "afl_version": _tool_output([str(afl), "-h"], env),
        "qemu_version": _tool_output([str(qemu_binary), "--version"], env),
        "runtime_seconds": runtime,
        "shard_count": shard_count,
        "timeout_ms": timeout_ms,
        "memory_limit_mb": memory_mb,
        "instrumentation": "afl++-qemu",
        "environment": {key: env[key] for key in ("GOMAXPROCS", "GOGC", "GODEBUG")},
        "plot_data_update_interval_seconds": int(env["AFL_FUZZER_STATS_UPDATE_INTERVAL"]),
        "afl_code_range": (
            {"AFL_CODE_START": code_range[0], "AFL_CODE_END": code_range[1]}
            if code_range is not None
            else "unresolved: nm found no github.com/free5gc/nas symbols; QEMU instrumented the full binary"
        ),
        "crash_reporting_caveat": "external core_pattern; missing-crash override enabled",
    }
    run_config_path = campaign / "matrix_run_config.json"
    if run_config_path.exists():
        existing_config = json.loads(run_config_path.read_text(encoding="utf-8"))
        for key in ("binary_sha256", "runtime_seconds", "timeout_ms", "memory_limit_mb", "shard_count"):
            if existing_config.get(key) != run_config.get(key):
                raise ValueError(f"existing matrix run config disagrees on {key}")
    else:
        run_config_path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")

    rows = []
    selected_indices = set(_matrix_plan_shard_indices(len(manifest["run_plan"]), shard_index, shard_count))
    for plan_index, entry in enumerate(manifest["run_plan"]):
        if plan_index not in selected_indices:
            continue
        model_name = entry["model"]
        model_id = model_slug(model_name)
        parser_name = entry["parser"]
        arm = entry["arm"]
        repeat = int(entry["repeat"])
        corpus = campaign / "corpora" / model_id / parser_name / arm
        output = campaign / "runs" / model_id / parser_name / f"rep_{repeat:02d}" / arm
        output.mkdir(parents=True, exist_ok=True)
        if any(output.iterdir()):
            raise FileExistsError(f"refusing to overwrite run output: {output}")
        command = [
            str(afl), "-Q", "-V", str(runtime), "-t", str(timeout_ms), "-m", str(memory_mb),
            "-s", str(entry["afl_seed"]), "-G", str(MAX_INPUT_BYTES), "-i", str(corpus), "-o", str(output),
            "--", str(binary), parser_name, "@@",
        ]
        started = time.monotonic()
        subprocess.run(command, cwd=ROOT / "vendor" / "free5gc" / "test", env=env, check=True)
        elapsed = time.monotonic() - started
        stats = parse_fuzzer_stats(output / "default" / "fuzzer_stats")
        plot_points = parse_plot_data(output / "default" / "plot_data")
        auc_value = coverage_auc(plot_points, runtime) if len(plot_points) >= 2 else None
        row: dict[str, str] = {
            "model": model_name,
            "model_id": model_id,
            "parser": parser_name,
            "repeat": str(repeat),
            "seed_arm": arm,
            "afl_seed": str(entry["afl_seed"]),
            "wall_clock_seconds": f"{elapsed:.3f}",
            "instrumentation": "afl++-qemu",
            "run_path": str(output.relative_to(campaign)),
            "coverage_auc_edge_seconds": f"{auc_value:.3f}" if auc_value is not None else "",
            "coverage_auc_mean_edges": f"{auc_value / runtime:.3f}" if auc_value is not None else "",
            "coverage_curve_samples": str(len(plot_points)),
            "coverage_auc_quality": "ok" if auc_value is not None else "insufficient_plot_data_samples",
        }
        for source, target in STAT_MAP.items():
            row[target] = stats.get(source, "")
        rows.append(row)

    return rows, []


def _matrix_plan_shard_indices(plan_length: int, shard_index: int, shard_count: int) -> list[int]:
    if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
        raise ValueError("shard index must be in [0, shard_count)")
    return [index for index in range(plan_length) if (index // 2) % shard_count == shard_index]


def summarize_paired_rows(
    rows: list[dict[str, str]], models: list[str], parsers: tuple[str, ...], repeats: int
) -> list[dict[str, str]]:
    metric_keys = (
        "executions", "executions_per_second", "corpus_found", "edges_found", "bitmap_coverage",
        "coverage_auc_edge_seconds", "coverage_auc_mean_edges",
    )
    indexed = {(row["model"], row["parser"], int(row["repeat"]), row["seed_arm"]): row for row in rows}
    deltas = []
    for model in models:
        for parser_name in parsers:
            for repeat in range(1, repeats + 1):
                ordinary = indexed[(model, parser_name, repeat, "ordinary")]
                llm = indexed[(model, parser_name, repeat, "llm")]
                result = {"model": model, "parser": parser_name, "repeat": str(repeat), "afl_seed": ordinary["afl_seed"]}
                for metric in metric_keys:
                    try:
                        left = float(ordinary.get(metric, "").rstrip("%"))
                        right = float(llm.get(metric, "").rstrip("%"))
                        result[f"llm_minus_ordinary_{metric}"] = f"{right - left:.4f}"
                    except (ValueError, AttributeError):
                        result[f"llm_minus_ordinary_{metric}"] = ""
                deltas.append(result)
    return deltas


def write_matrix_results(campaign: Path, rows: list[dict[str, str]], deltas: list[dict[str, str]]) -> None:
    config = json.loads((campaign / "matrix_run_config.json").read_text(encoding="utf-8"))
    manifest = json.loads((campaign / "matrix_manifest.json").read_text(encoding="utf-8"))
    write_coverage_analysis(campaign, rows, int(config["runtime_seconds"]))
    write_crash_triage_analysis(campaign, rows, Path(config["binary_path"]))
    for filename, content in (("matrix_results.csv", rows), ("paired_deltas.csv", deltas)):
        with (campaign / filename).open("x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(content[0]))
            writer.writeheader()
            writer.writerows(content)
    (campaign / "matrix_results.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    grouped: dict[tuple[str, str, str], list[float]] = {}
    for row in deltas:
        for key, value in row.items():
            if key.startswith("llm_minus_ordinary_") and value:
                grouped.setdefault((row["model"], row["parser"], key.removeprefix("llm_minus_ordinary_")), []).append(float(value))
    lines = [
        "# Repeated Multi-Model AFL++ Seed Study",
        "",
        "Phase 4 production benchmark: paired LLM-seed minus ordinary-seed deltas. Every repetition uses the same AFL RNG seed for both arms.",
        f"Matched design: `{config['runtime_seconds']}s` per run, `{manifest['repeats']}` paired repetitions per model/parser, plot_data update interval `{config.get('plot_data_update_interval_seconds', 'unknown')}s`.",
        "",
        "| Model | Parser | Metric | Median delta | Min | Max | n |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for (model, parser_name, metric), values in sorted(grouped.items()):
        lines.append(
            f"| {model} | {parser_name.upper()} | {metric} | {statistics.median(values):.4f} | "
            f"{min(values):.4f} | {max(values):.4f} | {len(values)} |"
        )
    lines.extend([
        "",
        "Report all model/parser cells, including neutral or negative deltas. Five repetitions improve on the earlier pilot but remain a modest sample; interpret the paired distribution and AUC curves rather than treating a single aggregate as conclusive. AFL++ QEMU edge totals include Go runtime/linker code, and the cluster core-dump handler can make crash reporting unreliable.",
        "",
        "Raw runs are in `matrix_results.csv`; paired deltas are in `paired_deltas.csv`; coverage curves/AUC are in `coverage_curves.svg`, `coverage_auc_paired.csv`, `coverage_auc_summary.csv`, and `coverage_analysis.json`; crash and length-case triage is in `crash_triage.json`.",
        "",
        "AUC is included only for runs with at least two distinct plot_data observations. Sparse runs remain visible in the curve exports and are listed in `coverage_analysis.json`; they are excluded from paired AUC comparisons.",
        "",
        "Complete configuration and run order are in `matrix_run_config.json` and `matrix_manifest.json`.",
    ])
    (campaign / "matrix_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _parse_seed_candidates(text: str) -> list[bytes]:
    value = json.loads(text)
    if isinstance(value, dict):
        value = value.get("hex_strings", value.get("seeds"))
    if not isinstance(value, list):
        raise ValueError("expected a JSON array of hex seeds")
    result: list[bytes] = []
    seen: set[bytes] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        cleaned = item.strip().removeprefix("0x").replace(" ", "").replace("\n", "")
        if len(cleaned) % 2 or (cleaned and not HEX_RE.fullmatch(cleaned)):
            continue
        try:
            seed = bytes.fromhex(cleaned)
        except ValueError:
            continue
        if not seed or len(seed) > MAX_INPUT_BYTES or seed in seen:
            continue
        seen.add(seed)
        result.append(seed)
    return result


def parse_seed_array(text: str, expected: int) -> list[bytes]:
    """Parse a JSON array of hexadecimal byte strings, failing closed."""
    result = _parse_seed_candidates(text)
    if len(result) >= expected:
        return result[:expected]
    raise ValueError(f"only {len(result)} unique valid seeds; expected {expected}")


def _ollama_chat(model: str, base_url: str, system: str, prompt: str) -> str:
    body = json.dumps(
        {
            "model": model,
            "stream": False,
            "format": "json",
            "options": {"num_predict": 1536, "temperature": 0.2},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"could not reach local Ollama at {base_url}: {exc}") from exc
    try:
        return str(payload["message"]["content"])
    except (KeyError, TypeError) as exc:
        raise RuntimeError("Ollama response did not contain message.content") from exc


def _request_ollama(
    model: str, base_url: str, parser: str, count: int, exclude: list[str] | None = None
) -> str:
    excluded = ", ".join(f'"{seed}"' for seed in (exclude or [])) or "none"
    prompt = (
        f"For 5G NAS {parser.upper()} offline parser tests, return exactly {count} "
        'unique even-length hex strings as JSON: {"hex_strings":["7e0043"]}. '
        f"Do not repeat these prior seeds: [{excluded}]. Include short, truncated, "
        "and plausible inputs. Output JSON only."
    )
    return _ollama_chat(model, base_url, "You generate defensive binary parser test inputs.", prompt)


def _request_ollama_structured(model: str, base_url: str, parser_name: str, archetype: str, count: int) -> str:
    prompt = _structured_spec_prompt(parser_name, archetype, count)
    return _ollama_chat(
        model, base_url, "You generate structured protocol test specs as JSON, grounded in real IE names.", prompt
    )


def _write_corpus(
    directory: Path,
    seeds: list[bytes],
    parser: str,
    seed_arm: str,
    source: str,
    model: str | None,
) -> list[dict[str, Any]]:
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty corpus: {directory}")
    records = []
    for index, seed in enumerate(seeds, 1):
        name = f"seed_{index:03d}.bin"
        (directory / name).write_bytes(seed)
        records.append(
            {
                "file": name,
                "parser": parser,
                "seed_arm": seed_arm,
                "sha256": hashlib.sha256(seed).hexdigest(),
                "size_bytes": len(seed),
                "source": source,
                "model": model,
            }
        )
    return records


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _free5gc_commit() -> str:
    checkout = ROOT / "vendor" / "free5gc"
    try:
        return subprocess.check_output(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def prepare_campaign(campaign: Path, count: int, model: str, base_url: str) -> None:
    if count < 2 or count > len(ORDINARY_SEEDS["gmm"]):
        raise ValueError("seed count must be between 2 and 8 for the built-in ordinary corpus")
    manifest_path = campaign / "seed_manifest.json"
    directories = [campaign / "corpus" / parser / arm for parser in PARSERS for arm in ("ordinary", "llm")]
    if manifest_path.exists() or any(directory.exists() for directory in directories):
        raise FileExistsError(f"refusing to overwrite existing campaign seed data: {campaign}")

    llm_seeds = {}
    for parser in PARSERS:
        generated: list[bytes] = []
        for _attempt in range(4):
            needed = count - len(generated)
            if needed == 0:
                break
            generated_text = _request_ollama(
                model,
                base_url,
                parser,
                needed,
                [seed.hex() for seed in generated],
            )
            for candidate in _parse_seed_candidates(generated_text):
                if candidate not in generated:
                    generated.append(candidate)
                if len(generated) == count:
                    break
        if len(generated) != count:
            raise ValueError(f"LLM returned only {len(generated)} unique {parser.upper()} seeds after four requests")
        llm_seeds[parser] = generated
    manifests = []
    overlap_by_parser = {}
    for parser in PARSERS:
        ordinary = [bytes.fromhex(seed) for seed in ORDINARY_SEEDS[parser][:count]]
        llm = llm_seeds[parser]
        if len(ordinary) != len(llm):
            raise ValueError("seed arms must have the same number of inputs")
        overlap_by_parser[parser] = len(
            {hashlib.sha256(seed).hexdigest() for seed in ordinary}
            & {hashlib.sha256(seed).hexdigest() for seed in llm}
        )
        ordinary_dir = campaign / "corpus" / parser / "ordinary"
        llm_dir = campaign / "corpus" / parser / "llm"
        manifests.extend(
            _write_corpus(ordinary_dir, ordinary, parser, "ordinary", "ordinary_protocol_templates", None)
        )
        manifests.extend(_write_corpus(llm_dir, llm, parser, "llm", "ollama_generated", model))
    manifest = {
        "schema_version": "afl-seed-comparison-v1",
        "model": model,
        "ollama_base_url": base_url,
        "seed_count_per_arm_per_parser": count,
        "input_limit_bytes": MAX_INPUT_BYTES,
        "free5gc_commit": _free5gc_commit(),
        "harness_path": str((ROOT / "harness" / "nas_parser" / "main.go").relative_to(ROOT)),
        "harness_sha256": _sha256(ROOT / "harness" / "nas_parser" / "main.go"),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "cross_arm_duplicate_inputs_by_parser": overlap_by_parser,
        "corpora": manifests,
    }
    campaign.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def parse_fuzzer_stats(path: Path) -> dict[str, str]:
    stats: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats


def parse_plot_data(path: Path) -> list[tuple[int, int]]:
    """Return ordered (seconds, edges_found) observations from AFL++ plot_data."""
    points: list[tuple[int, int]] = []
    header: list[str] | None = None
    with path.open(encoding="utf-8", newline="") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            fields = next(csv.reader([line]))
            if header is None:
                fields[0] = fields[0].lstrip("#").strip()
                header = [field.strip() for field in fields]
                if "relative_time" not in header or "edges_found" not in header:
                    raise ValueError(f"plot_data missing required columns: {path}")
                continue
            if len(fields) != len(header):
                continue
            record = dict(zip(header, (field.strip() for field in fields)))
            try:
                points.append((int(record["relative_time"]), int(record["edges_found"])))
            except (KeyError, ValueError):
                continue
    if not points:
        raise ValueError(f"plot_data contains no valid coverage observations: {path}")
    by_time: dict[int, int] = {}
    for elapsed, edges in points:
        if elapsed >= 0 and edges >= 0:
            by_time[elapsed] = edges
    if not by_time:
        raise ValueError(f"plot_data contains no non-negative observations: {path}")
    return sorted(by_time.items())


def coverage_auc(points: list[tuple[int, int]], duration_seconds: int) -> float:
    """Trapezoidal area under edges-found versus elapsed-seconds."""
    if duration_seconds <= 0 or not points:
        raise ValueError("coverage AUC requires points and a positive duration")
    bounded = [(min(max(time_s, 0), duration_seconds), edges) for time_s, edges in points]
    by_time = {time_s: edges for time_s, edges in bounded}
    ordered = sorted(by_time.items())
    if ordered[0][0] > 0:
        ordered.insert(0, (0, ordered[0][1]))
    if ordered[-1][0] < duration_seconds:
        ordered.append((duration_seconds, ordered[-1][1]))
    return sum(
        (right_time - left_time) * (left_edges + right_edges) / 2
        for (left_time, left_edges), (right_time, right_edges) in zip(ordered, ordered[1:])
    )


def coverage_at(points: list[tuple[int, int]], elapsed_seconds: int) -> float:
    """Linearly interpolate a coverage curve, holding endpoint values outside its range."""
    times = [point[0] for point in points]
    index = bisect.bisect_right(times, elapsed_seconds)
    if index == 0:
        return float(points[0][1])
    if index >= len(points):
        return float(points[-1][1])
    left_time, left_edges = points[index - 1]
    right_time, right_edges = points[index]
    if right_time == left_time:
        return float(right_edges)
    fraction = (elapsed_seconds - left_time) / (right_time - left_time)
    return left_edges + (right_edges - left_edges) * fraction


def write_coverage_analysis(campaign: Path, rows: list[dict[str, str]], duration_seconds: int) -> None:
    """Export per-run curves, paired AUC results, median curves, and an SVG plot."""
    curve_rows: list[dict[str, str]] = []
    points_by_key: dict[tuple[str, str, int, str], list[tuple[int, int]]] = {}
    auc_by_key: dict[tuple[str, str, int, str], float] = {}
    for row in rows:
        run_path = campaign / row["run_path"] / "default" / "plot_data"
        points = parse_plot_data(run_path)
        key = (row["model"], row["parser"], int(row["repeat"]), row["seed_arm"])
        points_by_key[key] = points
        auc_value = coverage_auc(points, duration_seconds) if len(points) >= 2 else None
        if auc_value is not None:
            auc_by_key[key] = auc_value
        row["coverage_auc_edge_seconds"] = f"{auc_value:.3f}" if auc_value is not None else ""
        row["coverage_auc_mean_edges"] = f"{auc_value / duration_seconds:.3f}" if auc_value is not None else ""
        row["coverage_curve_samples"] = str(len(points))
        row["coverage_auc_quality"] = "ok" if auc_value is not None else "insufficient_plot_data_samples"
        for elapsed, edges in points:
            curve_rows.append({
                "model": key[0], "parser": key[1], "repeat": str(key[2]), "seed_arm": key[3],
                "relative_time": str(elapsed), "edges_found": str(edges),
            })

    _write_csv(campaign / "coverage_curves.csv", curve_rows)

    paired_rows: list[dict[str, str]] = []
    grouped_deltas: dict[tuple[str, str], list[float]] = {}
    models = sorted({row["model"] for row in rows})
    parsers = sorted({row["parser"] for row in rows})
    repeats = sorted({int(row["repeat"]) for row in rows})
    for model in models:
        for parser_name in parsers:
            for repeat in repeats:
                ordinary_key = (model, parser_name, repeat, "ordinary")
                llm_key = (model, parser_name, repeat, "llm")
                if ordinary_key not in auc_by_key or llm_key not in auc_by_key:
                    continue
                ordinary_auc = auc_by_key[ordinary_key]
                llm_auc = auc_by_key[llm_key]
                delta = llm_auc - ordinary_auc
                grouped_deltas.setdefault((model, parser_name), []).append(delta)
                paired_rows.append({
                    "model": model, "parser": parser_name, "repeat": str(repeat),
                    "ordinary_auc_edge_seconds": f"{ordinary_auc:.3f}",
                    "llm_auc_edge_seconds": f"{llm_auc:.3f}",
                    "llm_minus_ordinary_auc_edge_seconds": f"{delta:.3f}",
                    "llm_minus_ordinary_mean_edges": f"{delta / duration_seconds:.3f}",
                })
    _write_csv(campaign / "coverage_auc_paired.csv", paired_rows)

    summary_rows: list[dict[str, str]] = []
    for (model, parser_name), values in sorted(grouped_deltas.items()):
        summary_rows.append({
            "model": model, "parser": parser_name, "paired_repeats": str(len(values)),
            "median_llm_minus_ordinary_edge_seconds": f"{statistics.median(values):.3f}",
            "min_llm_minus_ordinary_edge_seconds": f"{min(values):.3f}",
            "max_llm_minus_ordinary_edge_seconds": f"{max(values):.3f}",
            "median_llm_minus_ordinary_mean_edges": f"{statistics.median(values) / duration_seconds:.3f}",
        })
    _write_csv(campaign / "coverage_auc_summary.csv", summary_rows)

    grid = sorted(set(range(0, duration_seconds + 1, 5)) | {duration_seconds})
    summary_curve_rows: list[dict[str, str]] = []
    for model in models:
        for parser_name in parsers:
            for arm in ("ordinary", "llm"):
                matching = [
                    points for (m, p, _repeat, a), points in points_by_key.items()
                    if (m, p, a) == (model, parser_name, arm)
                ]
                for elapsed in grid:
                    values = [coverage_at(points, elapsed) for points in matching]
                    if values:
                        summary_curve_rows.append({
                            "model": model, "parser": parser_name, "seed_arm": arm,
                            "relative_time": str(elapsed),
                            "median_edges_found": f"{statistics.median(values):.3f}",
                            "mean_edges_found": f"{statistics.mean(values):.3f}",
                            "repeat_count": str(len(values)),
                        })
    _write_csv(campaign / "coverage_curve_summary.csv", summary_curve_rows)
    _write_coverage_svg(campaign / "coverage_curves.svg", summary_curve_rows, models, parsers, duration_seconds)
    sample_counts = [len(points) for points in points_by_key.values()]
    expected_pairs = len(models) * len(parsers) * len({key[2] for key in points_by_key})
    quality = {
        "duration_seconds": duration_seconds,
        "plot_data_sampling_interval_seconds": 5,
        "auc_method": "trapezoidal over raw observations; first observed coverage held back to t=0 and last held to run duration",
        "minimum_plot_data_samples_per_run": min(sample_counts, default=0),
        "median_plot_data_samples_per_run": statistics.median(sample_counts) if sample_counts else 0,
        "maximum_plot_data_samples_per_run": max(sample_counts, default=0),
        "runs_with_insufficient_samples": [
            {"model": key[0], "parser": key[1], "repeat": key[2], "seed_arm": key[3], "samples": len(points)}
            for key, points in points_by_key.items() if len(points) < 2
        ],
        "paired_auc_comparisons": len(paired_rows),
        "expected_paired_auc_comparisons": expected_pairs,
    }
    (campaign / "coverage_analysis.json").write_text(json.dumps(quality, indent=2) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _write_coverage_svg(
    path: Path, rows: list[dict[str, str]], models: list[str], parsers: list[str], duration_seconds: int
) -> None:
    width, height = 1120, 740
    panel_width, panel_height = 500, 300
    colors = {"ordinary": "#217a57", "llm": "#c34b36"}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">']
    parts.extend(['<rect width="100%" height="100%" fill="#fff"/>', '<style>text{font-family:Arial,sans-serif;fill:#242a2e}.grid{stroke:#d9dfdc;stroke-width:1}.axis{stroke:#56615c;stroke-width:1.2}</style>'])
    for panel_index, (model, parser_name) in enumerate((m, p) for m in models for p in parsers):
        column, row_index = panel_index % 2, panel_index // 2
        left, top = 72 + column * 540, 52 + row_index * 350
        plot_left, plot_top = left + 55, top + 38
        plot_width, plot_height = panel_width - 78, panel_height - 78
        matching = [row for row in rows if row["model"] == model and row["parser"] == parser_name]
        maximum = max((float(row["median_edges_found"]) for row in matching), default=1.0) or 1.0
        parts.append(f'<text x="{left}" y="{top + 15}" font-size="15" font-weight="bold">{html.escape(model)} / {html.escape(parser_name.upper())}</text>')
        for fraction in (0, 0.25, 0.5, 0.75, 1):
            y = plot_top + plot_height * (1 - fraction)
            value = maximum * fraction
            parts.append(f'<line class="grid" x1="{plot_left}" y1="{y:.1f}" x2="{plot_left + plot_width}" y2="{y:.1f}"/>')
            parts.append(f'<text x="{plot_left - 8}" y="{y + 4:.1f}" text-anchor="end" font-size="10">{value:.0f}</text>')
        parts.append(f'<line class="axis" x1="{plot_left}" y1="{plot_top + plot_height}" x2="{plot_left + plot_width}" y2="{plot_top + plot_height}"/>')
        parts.append(f'<line class="axis" x1="{plot_left}" y1="{plot_top}" x2="{plot_left}" y2="{plot_top + plot_height}"/>')
        for elapsed in sorted({0, duration_seconds // 2, duration_seconds}):
            x = plot_left + plot_width * elapsed / duration_seconds
            parts.append(f'<text x="{x:.1f}" y="{plot_top + plot_height + 17}" text-anchor="middle" font-size="10">{elapsed}</text>')
        for arm_index, arm in enumerate(("ordinary", "llm")):
            curve = sorted(
                (row for row in matching if row["seed_arm"] == arm), key=lambda item: int(item["relative_time"])
            )
            coords = []
            for point in curve:
                x = plot_left + plot_width * int(point["relative_time"]) / duration_seconds
                y = plot_top + plot_height * (1 - float(point["median_edges_found"]) / maximum)
                coords.append(f"{x:.1f},{y:.1f}")
            if coords:
                parts.append(f'<polyline fill="none" stroke="{colors[arm]}" stroke-width="2.5" points="{" ".join(coords)}"/>')
            legend_x = plot_left + 8 + arm_index * 145
            legend_y = plot_top + plot_height + 40
            parts.append(f'<line x1="{legend_x}" y1="{legend_y}" x2="{legend_x + 24}" y2="{legend_y}" stroke="{colors[arm]}" stroke-width="3"/>')
            parts.append(f'<text x="{legend_x + 30}" y="{legend_y + 4}" font-size="11">{arm} (median)</text>')
        parts.append(f'<text x="{plot_left + plot_width / 2:.1f}" y="{top + panel_height - 2}" text-anchor="middle" font-size="11">Elapsed time (seconds)</text>')
    parts.append(f'<text x="16" y="{height / 2}" transform="rotate(-90 16 {height / 2})" text-anchor="middle" font-size="12">Edges found</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def write_crash_triage_analysis(campaign: Path, rows: list[dict[str, str]], binary: Path) -> None:
    """Cross-reference unique AFL paths/crashes with curated length cases and replay artifacts."""
    triage_path = ROOT / "data" / "results" / "nas_curated_seed_suite_20261002_v2" / "parser_acceptance_triage.md"
    seed_suite_path = ROOT / "data" / "raw" / "nas_seed_suite_20261002" / "seeds.json"
    triage_names = {
        "gmm_security_capability_cut_mid_value",
        "gsm_capability_length_ff_short_payload",
        "gsm_extended_pco_length_exceeds_remaining",
        "gsm_capability_cut_mid_value",
    }
    seeds = json.loads(seed_suite_path.read_text(encoding="utf-8"))
    triage_seeds = {item["name"]: bytes.fromhex(item["hex"]) for item in seeds if item["name"] in triage_names}
    triage_hashes = {hashlib.sha256(seed).hexdigest(): name for name, seed in triage_seeds.items()}
    frontier_hashes: dict[str, dict[str, Any]] = {}
    frontier_bytes: dict[str, bytes] = {}
    crashes: dict[str, dict[str, Any]] = {}
    hangs: dict[str, dict[str, Any]] = {}
    run_artifact_counts: list[dict[str, Any]] = []

    def collect_artifacts(folder: Path, destination: dict[str, dict[str, Any]], run_info: dict[str, Any]) -> int:
        found = 0
        if not folder.is_dir():
            return found
        for item in sorted(folder.iterdir()):
            if not item.is_file() or not item.name.startswith("id:"):
                continue
            raw = item.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            found += 1
            record = destination.setdefault(digest, {
                "sha256": digest, "size_bytes": len(raw), "runs": [], "triage_case": triage_hashes.get(digest),
            })
            record["runs"].append(run_info)
        return found

    for row in rows:
        run_dir = campaign / row["run_path"] / "default"
        run_info = {key: row[key] for key in ("model", "parser", "repeat", "seed_arm", "run_path")}
        queue_dir = run_dir / "queue"
        frontier_count = 0
        if queue_dir.is_dir():
            for item in queue_dir.iterdir():
                if not item.is_file() or not item.name.endswith(",+cov"):
                    continue
                raw = item.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                frontier_count += 1
                record = frontier_hashes.setdefault(digest, {
                    "sha256": digest, "size_bytes": len(raw), "triage_case": triage_hashes.get(digest),
                    "runs": [], "queue_names": [],
                })
                record["runs"].append(run_info)
                record["queue_names"].append(item.name)
                frontier_bytes[digest] = raw
        crash_count = collect_artifacts(run_dir / "crashes", crashes, run_info)
        hang_count = collect_artifacts(run_dir / "hangs", hangs, run_info)
        run_artifact_counts.append({
            **run_info, "frontier_paths": frontier_count,
            "saved_crash_files": crash_count, "saved_hang_files": hang_count,
        })

    compiler = _build_seed_compiler(campaign)
    triage_order = list(triage_seeds)
    triage_results = []
    frontier_parse_results: list[dict[str, Any]] = []
    for parser_name in PARSERS:
        digests = sorted(
            digest for digest, record in frontier_hashes.items()
            if any(run["parser"] == parser_name for run in record["runs"])
        )
        outcomes = dissect_seeds(compiler, parser_name, [frontier_bytes[digest] for digest in digests])
        for digest, outcome in zip(digests, outcomes):
            frontier_parse_results.append({
                "sha256": digest,
                "size_bytes": frontier_hashes[digest]["size_bytes"],
                "triage_case": frontier_hashes[digest]["triage_case"],
                "parse_result": outcome,
                "runs": frontier_hashes[digest]["runs"],
                "queue_names": frontier_hashes[digest]["queue_names"],
            })
    for parser_name in PARSERS:
        names_for_parser = [name for name in triage_order if name.startswith(parser_name + "_")]
        payload_by_name = {item["name"]: item for item in seeds if item["name"] in names_for_parser}
        outcomes = dissect_seeds(
            compiler, parser_name, [triage_seeds[name] for name in names_for_parser]
        )
        for name, outcome in zip(names_for_parser, outcomes):
            triage_results.append({
                "name": name, "parser": parser_name, "sha256": hashlib.sha256(triage_seeds[name]).hexdigest(),
                "dissector_result": outcome, "description": payload_by_name[name].get("description", ""),
                "frontier_exact_matches": [digest for digest, record in frontier_hashes.items() if record["triage_case"] == name],
                "crash_exact_matches": [digest for digest, record in crashes.items() if record["triage_case"] == name],
            })

    def replay_saved_inputs(records: dict[str, dict[str, Any]], parser_by_hash: dict[str, str]) -> list[dict[str, Any]]:
        replay_results = []
        with tempfile.TemporaryDirectory() as temp_dir:
            for digest, record in sorted(records.items()):
                candidate = Path(temp_dir) / f"{digest}.bin"
                # Reconstruct the unique bytes from the first associated AFL artifact path.
                first_run = record["runs"][0]
                folder = campaign / first_run["run_path"] / "default" / ("crashes" if records is crashes else "hangs")
                artifact = next(
                    path for path in folder.iterdir()
                    if path.is_file() and path.name.startswith("id:") and hashlib.sha256(path.read_bytes()).hexdigest() == digest
                )
                candidate.write_bytes(artifact.read_bytes())
                parser_name = parser_by_hash[digest]
                try:
                    replay = subprocess.run(
                        [str(binary), parser_name, str(candidate)], cwd=ROOT / "vendor" / "free5gc" / "test",
                        check=False, capture_output=True, text=True, timeout=5,
                    )
                    replay_results.append({
                        "sha256": digest, "parser": parser_name, "exit_code": replay.returncode,
                        "stdout_tail": replay.stdout[-500:], "stderr_tail": replay.stderr[-1500:],
                        "panic_or_process_fault": replay.returncode != 0,
                    })
                except subprocess.TimeoutExpired as exc:
                    replay_results.append({
                        "sha256": digest, "parser": parser_name, "timed_out_on_replay": True,
                        "stderr_tail": (exc.stderr or b"").decode(errors="replace")[-1500:],
                    })
        return replay_results

    crash_parsers = {digest: record["runs"][0]["parser"] for digest, record in crashes.items()}
    hang_parsers = {digest: record["runs"][0]["parser"] for digest, record in hangs.items()}
    parser_rejected_frontier = [
        record for record in frontier_parse_results if not record["parse_result"].get("ok")
    ]
    frontier_path_counts_by_arm = {
        arm: len({
            record["sha256"] for record in frontier_parse_results
            if any(run["seed_arm"] == arm for run in record["runs"])
        })
        for arm in ("ordinary", "llm")
    }
    report = {
        "triage_source": str(triage_path.relative_to(ROOT)),
        "triage_scope_note": "The four length cases are documented candidates, not confirmed bugs; exact byte matches only are reported.",
        "unique_frontier_path_count": len(frontier_hashes),
        "unique_frontier_path_exact_triage_matches": [record for record in frontier_hashes.values() if record["triage_case"]],
        "frontier_path_parser_results": frontier_parse_results,
        "frontier_paths_with_parser_errors": parser_rejected_frontier,
        "unique_frontier_path_counts_by_seed_arm": frontier_path_counts_by_arm,
        "documented_length_cases": triage_results,
        "unique_saved_crash_count": len(crashes),
        "unique_saved_hang_count": len(hangs),
        "saved_crashes": list(crashes.values()),
        "saved_hangs": list(hangs.values()),
        "crash_replays": replay_saved_inputs(crashes, crash_parsers),
        "hang_replays": replay_saved_inputs(hangs, hang_parsers),
        "per_run_artifact_counts": run_artifact_counts,
        "crash_reporting_caveat": "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; external cluster core_pattern can delay or suppress saved crash artifacts.",
        "interpretation": "A zero crash/hang count and no exact queue match do not establish parser safety or rule out related malformed-length behavior.",
    }
    (campaign / "crash_triage.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _build_target(campaign: Path, go: Path | None = None) -> Path:
    go_binary = go or (Path.home() / "opt" / "go" / "bin" / "go")
    test_module = ROOT / "vendor" / "free5gc" / "test"
    harness = ROOT / "harness" / "nas_parser" / "main.go"
    if not go_binary.is_file():
        raise FileNotFoundError(f"Go executable not found: {go_binary}")
    if not (test_module / "go.mod").is_file():
        raise FileNotFoundError(f"free5GC test module not found: {test_module}")
    target_dir = campaign / "artifacts"
    target_dir.mkdir(parents=True, exist_ok=True)
    binary = target_dir / "free5gc-nas-afl"
    env = os.environ.copy()
    env["GOROOT"] = str(go_binary.parent.parent)
    env["PATH"] = str(go_binary.parent) + os.pathsep + env.get("PATH", "")
    subprocess.run(
        [str(go_binary), "build", "-trimpath", "-o", str(binary), str(harness)],
        cwd=test_module,
        env=env,
        check=True,
    )
    return binary


def _afl_binary(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path.home() / "opt" / "afl" / "bin" / "afl-fuzz"


def _afl_showmap_binary(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    return Path.home() / "opt" / "afl" / "bin" / "afl-showmap"


# Phase 2.2: narrow QEMU instrumentation to the free5gc/nas package code so
# Go runtime/scheduler/GC addresses contribute less edge noise. Best-effort
# only: if `nm` is unavailable or finds no matching symbols, callers must
# proceed without AFL_CODE_START/END rather than fail the whole run, but the
# fallback is always recorded (never silently skipped without a trace).
NAS_SYMBOL_MARKER = "github.com/free5gc/nas"


def _resolve_nas_code_range(binary: Path) -> tuple[str, str] | None:
    try:
        result = subprocess.run(
            ["nm", "-S", "--defined-only", str(binary)], capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    start: int | None = None
    end: int | None = None
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or NAS_SYMBOL_MARKER not in parts[3]:
            continue
        try:
            address = int(parts[0], 16)
            size = int(parts[1], 16)
        except ValueError:
            continue
        if start is None or address < start:
            start = address
        candidate_end = address + size
        if end is None or candidate_end > end:
            end = candidate_end
    if start is None or end is None:
        return None
    return f"0x{start:x}", f"0x{end:x}"


def _tool_output(command: list[str], env: dict[str, str]) -> str:
    try:
        result = subprocess.run(command, env=env, check=False, capture_output=True, text=True)
        lines = (result.stdout + result.stderr).strip().splitlines()
        return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", lines[0]) if lines else "unknown"
    except (OSError, IndexError):
        return "unknown"


def run_comparison(
    campaign: Path,
    binary: Path | None,
    afl: Path,
    runtime: int,
    timeout_ms: int,
    memory_mb: int,
    random_seed: int,
    go_binary: Path | None = None,
) -> list[dict[str, str]]:
    rows = []
    env = os.environ.copy()
    env["AFL_PATH"] = str(afl.parent.parent / "lib" / "afl")
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["GOMAXPROCS"] = "1"
    env["GOGC"] = "off"
    env["GODEBUG"] = "asyncpreemptoff=1,gctrace=0"
    selected_go = go_binary or (Path.home() / "opt" / "go" / "bin" / "go")
    env["GOROOT"] = str(selected_go.parent.parent)
    env["PATH"] = str(selected_go.parent) + os.pathsep + env.get("PATH", "")
    if binary is None:
        binary = _build_target(campaign, selected_go)
    elif not binary.is_file():
        raise FileNotFoundError(f"target binary missing: {binary}")
    config_path = campaign / "run_config.json"
    if config_path.exists():
        raise FileExistsError(f"refusing to overwrite run configuration: {config_path}")
    qemu_binary = afl.parent / "afl-qemu-trace"
    code_range = _resolve_nas_code_range(binary)
    if code_range is not None:
        env["AFL_CODE_START"], env["AFL_CODE_END"] = code_range
    run_config = {
        "schema_version": "afl-matched-run-v1",
        "free5gc_commit": _free5gc_commit(),
        "harness_path": str((ROOT / "harness" / "nas_parser" / "main.go").relative_to(ROOT)),
        "harness_sha256": _sha256(ROOT / "harness" / "nas_parser" / "main.go"),
        "binary_path": str(binary),
        "binary_sha256": _sha256(binary),
        "go_version": _tool_output([str(selected_go), "version"], env),
        "afl_version": _tool_output([str(afl), "-h"], env),
        "qemu_version": _tool_output([str(qemu_binary), "--version"], env),
        "instrumentation": "afl++-qemu",
        "runtime_seconds": runtime,
        "timeout_ms": timeout_ms,
        "memory_limit_mb": memory_mb,
        "afl_random_seed": random_seed,
        "environment": {key: env[key] for key in ("GOMAXPROCS", "GOGC", "GODEBUG")},
        "afl_code_range": (
            {"AFL_CODE_START": code_range[0], "AFL_CODE_END": code_range[1]}
            if code_range is not None
            else "unresolved: nm found no github.com/free5gc/nas symbols; QEMU instrumented the full binary"
        ),
        "crash_reporting": "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; cluster core_pattern routes dumps externally",
        "run_order": [f"{target}/{arm}" for target in PARSERS for arm in ("ordinary", "llm")],
    }
    config_path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")

    for parser in PARSERS:
        for arm in ("ordinary", "llm"):
            corpus = campaign / "corpus" / parser / arm
            if not corpus.is_dir() or not any(corpus.iterdir()):
                raise FileNotFoundError(f"missing seed corpus: {corpus}; run prepare first")
            output = campaign / "runs" / parser / arm
            output.mkdir(parents=True, exist_ok=True)
            if any(output.iterdir()):
                raise FileExistsError(f"refusing to overwrite existing run output: {output}")
            command = [
                str(afl),
                "-Q",
                "-V", str(runtime),
                "-t", str(timeout_ms),
                "-m", str(memory_mb),
                "-s", str(random_seed),
                "-G", str(MAX_INPUT_BYTES),
                "-i", str(corpus),
                "-o", str(output),
                "--", str(binary), parser, "@@",
            ]
            started = time.monotonic()
            subprocess.run(command, cwd=ROOT / "vendor" / "free5gc" / "test", env=env, check=True)
            elapsed = time.monotonic() - started
            stats_path = output / "default" / "fuzzer_stats"
            stats = parse_fuzzer_stats(stats_path)
            row = {"parser": parser, "seed_arm": arm, "expected_runtime_seconds": str(runtime)}
            row["wall_clock_seconds"] = f"{elapsed:.3f}"
            row["instrumentation"] = "afl++-qemu"
            row["crash_reporting_caveat"] = "external_core_pattern"
            for source, target in STAT_MAP.items():
                row[target] = stats.get(source, "")
            rows.append(row)
    return rows


def write_results(campaign: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0])
    csv_path = campaign / "results.csv"
    json_path = campaign / "results.json"
    with csv_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    with json_path.open("x", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)
        handle.write("\n")
    write_report(campaign, rows)


def write_report(campaign: Path, rows: list[dict[str, str]]) -> None:
    manifest_path = campaign / "seed_manifest.json"
    config_path = campaign / "run_config.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    afl_version = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", config.get("afl_version", "unknown"))
    by_key = {(row["parser"], row["seed_arm"]): row for row in rows}
    metric_specs = (
        ("Runtime (s)", "runtime_seconds"),
        ("Executions", "executions"),
        ("Executions/s", "executions_per_second"),
        ("Final corpus", "final_corpus"),
        ("Corpus found", "corpus_found"),
        ("Maximum depth", "maximum_depth"),
        ("Bitmap coverage", "bitmap_coverage"),
        ("Edges/map slots observed", "edges_found"),
        ("Map capacity (slots)", "total_edges"),
        ("Saved crashes", "saved_crashes"),
        ("Saved hangs", "saved_hangs"),
        ("Timeouts", "timeouts"),
        ("Stability", "stability"),
    )
    columns = (("GMM", "ordinary"), ("GMM", "llm"), ("GSM", "ordinary"), ("GSM", "llm"))
    lines = [
        "# AFL++ NAS Seed Comparison",
        "",
        f"Campaign: `{campaign.name}`",
        f"free5GC commit: `{config.get('free5gc_commit', manifest.get('free5gc_commit', 'unknown'))}`",
        f"LLM: `{manifest.get('model', 'unknown')}`; seeds/arm/parser: `{manifest.get('seed_count_per_arm_per_parser', 'unknown')}`",
        f"AFL++: `{afl_version}`; instrumentation: `{config.get('instrumentation', 'unknown')}`",
        f"Matched settings: `{config.get('runtime_seconds', 'unknown')}s`, timeout `{config.get('timeout_ms', 'unknown')}ms`, memory `{config.get('memory_limit_mb', 'unknown')}MB`, AFL seed `{config.get('afl_random_seed', 'unknown')}`.",
        "",
        "| Metric | GMM ordinary | GMM LLM seeds | GSM ordinary | GSM LLM seeds |",
        "|---|---:|---:|---:|---:|",
    ]
    for label, key in metric_specs:
        cells = []
        for parser_name, arm in columns:
            value = by_key.get((parser_name.lower(), arm), {}).get(key, "")
            if key == "edges_found" and value:
                total = by_key[(parser_name.lower(), arm)].get("total_edges", "")
                value = f"{value} / {total}" if total else value
            cells.append(value or "n/a")
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    overlaps = manifest.get("cross_arm_duplicate_inputs_by_parser", {})
    lines.extend(
        [
        "Paired area-under-curve (AUC) values use trapezoidal integration over each run's raw AFL++ `plot_data` observations and are reported in edge-seconds with a duration-normalized mean edge count. Median curves are interpolated onto a five-second grid. See `coverage_curves.svg`, `coverage_curves.csv`, `coverage_curve_summary.csv`, `coverage_auc_paired.csv`, and `coverage_auc_summary.csv`.",
        "",
        "AFL++ QEMU coverage includes Go runtime/linker code, and the cluster core-dump handler can make crash reporting unreliable. Zero saved crashes/hangs is not evidence that the parser is free of defects. See `crash_triage.json` for saved-artifact replay and cross-references to the candidate length-validation cases.",
            f"Seed overlaps across arms: GMM `{overlaps.get('gmm', 'unknown')}`, GSM `{overlaps.get('gsm', 'unknown')}`.",
        "Raw runs are in `matrix_results.csv`; paired deltas are in `paired_deltas.csv`; complete configuration and run order are in `matrix_run_config.json` and `matrix_manifest.json`.",
            "## Interpretation",
            "",
            "This is a short pilot (one 30-second trial per cell), not a statistically powered comparison. AFL++ emitted instrumentation-instability warnings for the Go binary under QEMU, and coverage includes Go runtime/linker code as well as NAS parser code. Small edge/corpus differences should therefore be treated as exploratory only.",
            "",
            "The host routes core dumps through an external handler. Runs used `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`; crash reporting may be delayed or unreliable. Zero saved crashes/hangs/timeouts is not evidence that the parser is free of defects.",
            "",
            "Raw AFL++ statistics are in each `runs/<parser>/<arm>/default/fuzzer_stats`; seed hashes and sizes are in `seed_manifest.json`; binary/toolchain details are in `run_config.json`.",
            "",
        ]
    )
    report_path = campaign / "results.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")


# Phase 2.3: repeatability check. Runs the same corpus through AFL++ with the
# same random seed N times to measure instrumentation stability in isolation
# from any LLM-vs-ordinary comparison.
STABILITY_THRESHOLD_PERCENT = 98.0


def run_repeatability_check(
    campaign: Path,
    corpus: Path,
    parser_name: str,
    afl: Path,
    runtime: int,
    timeout_ms: int,
    memory_mb: int,
    afl_seed: int,
    repeats: int,
    go_binary: Path | None = None,
) -> list[dict[str, str]]:
    if parser_name not in PARSERS:
        raise ValueError(f"parser must be one of {PARSERS}")
    if repeats < 2:
        raise ValueError("repeatability check needs at least two repeats")
    if not corpus.is_dir() or not any(corpus.iterdir()):
        raise FileNotFoundError(f"missing seed corpus: {corpus}")
    if (campaign / "repeatability_run_config.json").exists():
        raise FileExistsError(f"repeatability check already exists under {campaign}")

    selected_go = go_binary or (Path.home() / "opt" / "go" / "bin" / "go")
    env = os.environ.copy()
    env["AFL_PATH"] = str(afl.parent.parent / "lib" / "afl")
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env.update({"GOMAXPROCS": "1", "GOGC": "off", "GODEBUG": "asyncpreemptoff=1,gctrace=0"})
    env["GOROOT"] = str(selected_go.parent.parent)
    env["PATH"] = os.pathsep.join((str(afl.parent), str(selected_go.parent), env.get("PATH", "")))
    binary = _build_target(campaign, selected_go)
    code_range = _resolve_nas_code_range(binary)
    if code_range is not None:
        env["AFL_CODE_START"], env["AFL_CODE_END"] = code_range

    run_config = {
        "schema_version": "afl-repeatability-check-v1",
        "parser": parser_name,
        "corpus": str(corpus),
        "repeats": repeats,
        "afl_seed": afl_seed,
        "runtime_seconds": runtime,
        "timeout_ms": timeout_ms,
        "memory_limit_mb": memory_mb,
        "environment": {key: env[key] for key in ("GOMAXPROCS", "GOGC", "GODEBUG")},
        "afl_code_range": (
            {"AFL_CODE_START": code_range[0], "AFL_CODE_END": code_range[1]}
            if code_range is not None
            else "unresolved: nm found no github.com/free5gc/nas symbols; QEMU instrumented the full binary"
        ),
    }
    campaign.mkdir(parents=True, exist_ok=True)
    (campaign / "repeatability_run_config.json").write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")

    rows: list[dict[str, str]] = []
    for repeat in range(1, repeats + 1):
        output = campaign / "runs" / f"rep_{repeat:02d}"
        output.mkdir(parents=True, exist_ok=True)
        if any(output.iterdir()):
            raise FileExistsError(f"refusing to overwrite run output: {output}")
        command = [
            str(afl), "-Q", "-V", str(runtime), "-t", str(timeout_ms), "-m", str(memory_mb),
            "-s", str(afl_seed), "-G", str(MAX_INPUT_BYTES), "-i", str(corpus), "-o", str(output),
            "--", str(binary), parser_name, "@@",
        ]
        started = time.monotonic()
        subprocess.run(command, cwd=ROOT / "vendor" / "free5gc" / "test", env=env, check=True)
        elapsed = time.monotonic() - started
        stats = parse_fuzzer_stats(output / "default" / "fuzzer_stats")
        row = {
            "repeat": str(repeat), "parser": parser_name, "afl_seed": str(afl_seed),
            "wall_clock_seconds": f"{elapsed:.3f}",
        }
        for source, target in STAT_MAP.items():
            row[target] = stats.get(source, "")
        rows.append(row)
    return rows


def write_repeatability_report(campaign: Path, rows: list[dict[str, str]]) -> dict[str, Any]:
    if not rows:
        raise ValueError("no repeatability rows to report")
    fieldnames = list(rows[0])
    with (campaign / "repeatability_results.csv").open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    (campaign / "repeatability_results.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")

    stabilities = []
    for row in rows:
        try:
            stabilities.append(float(row.get("stability", "").rstrip("%")))
        except ValueError:
            continue
    if not stabilities:
        raise ValueError("no run reported a parsable stability percentage")
    min_stability = min(stabilities)
    median_stability = statistics.median(stabilities)
    passed = min_stability >= STABILITY_THRESHOLD_PERCENT

    lines = [
        "# AFL++ Repeatability Check",
        "",
        f"{len(rows)} identical runs: same corpus, same AFL random seed (`{rows[0]['afl_seed']}`), "
        f"same parser (`{rows[0]['parser']}`).",
        "",
        "| Repeat | Stability | Executions | Edges found | Bitmap coverage |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['repeat']} | {row.get('stability', '')} | {row.get('executions', '')} | "
            f"{row.get('edges_found', '')} | {row.get('bitmap_coverage', '')} |"
        )
    lines.extend([
        "",
        f"Median stability: {median_stability:.2f}%. Minimum stability: {min_stability:.2f}%. "
        f"Threshold: {STABILITY_THRESHOLD_PERCENT:.0f}%.",
        "",
    ])
    if passed:
        lines.append(
            "PASS: minimum stability meets the threshold across all repeats. This does not by itself "
            "prove any specific paired delta is real, but single-digit deltas are less likely to be "
            "pure instrumentation noise at this stability level."
        )
    else:
        lines.append(
            "FAIL: minimum stability is below the threshold. Per policy, treat single-digit edge/"
            "coverage deltas in paired LLM-vs-ordinary comparisons on this target as experimental "
            "noise, not evidence of a real effect, until instrumentation stability improves."
        )
    (campaign / "repeatability_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"min_stability_percent": min_stability, "median_stability_percent": median_stability, "passed": passed}


# Phase 3: dynamic coverage-guided feedback loop. 3.1 identifies which queue
# entries from a completed AFL++ run unlocked new coverage; 3.2 asks a model
# for variants of only the specific IE one such entry reached (or failed at),
# via the same base_hex/replace_ie_value compiler path validated above; 3.3
# locally confirms (via afl-showmap, not trust) that a candidate actually
# hits new edges before it is allowed into a round-2 corpus.
def extract_frontier_seeds(queue_dir: Path) -> list[Path]:
    """Return queue entries AFL++ marked as unlocking new coverage (`+cov`),
    excluding the initial seeds supplied via -i (tagged `,orig:`). AFL++ also
    keeps some non-`+cov` entries (e.g. trimmed duplicates of an existing
    queue item); those did not unlock a new branch and are deliberately
    excluded here.
    """
    if not queue_dir.is_dir():
        raise FileNotFoundError(f"queue directory not found: {queue_dir}")
    frontier = []
    for path in sorted(queue_dir.iterdir()):
        name = path.name
        if not path.is_file() or name.startswith("."):
            continue
        if ",orig:" in name:
            continue
        if name.endswith(",+cov"):
            frontier.append(path)
    return frontier


def dissect_seeds(dissector_binary: Path, parser_name: str, seeds: list[bytes]) -> list[dict[str, Any]]:
    """Run seeds through the real free5gc/nas parser (Phase 3.1/3.2's
    "dissector"): reports which IEs a successfully-parsed seed populated, or
    free5gc's own error string (already IE-specific) for a rejected one.
    """
    if not seeds:
        return []
    stdin_text = "\n".join(json.dumps({"parser": parser_name, "hex": seed.hex()}) for seed in seeds) + "\n"
    result = subprocess.run(
        [str(dissector_binary), "dissect"], input=stdin_text, capture_output=True, text=True, check=True
    )
    lines = result.stdout.strip("\n").split("\n")
    if len(lines) != len(seeds):
        raise RuntimeError(f"dissector returned {len(lines)} results for {len(seeds)} seeds")
    return [json.loads(line) for line in lines]


def _coverage_gap_prompt(parser_name: str, ie_name: str, current_value_hex: str, count: int) -> str:
    message_type = MESSAGE_TYPE_BY_PARSER[parser_name]
    return (
        f"This {parser_name.upper()} seed ({message_type}) reached the \"{ie_name}\" IE with current "
        f'value hex "{current_value_hex}". Provide {count} alternative hex values for ONLY this IE\'s '
        "value bytes, keeping every other IE and the outer message envelope unchanged. Vary the byte "
        "content and length (including edge lengths like 0 or 1 byte) to probe cases this exact value "
        'did not. Emit ONLY a JSON object {"value_hex_variants": ["...", ...]} with exactly '
        f"{count} unique even-length hex strings. Output JSON only."
    )


def _request_coverage_gap_variants(
    model: str, base_url: str, parser_name: str, ie_name: str, current_value_hex: str, count: int
) -> str:
    prompt = _coverage_gap_prompt(parser_name, ie_name, current_value_hex, count)
    return _ollama_chat(
        model, base_url,
        "You generate targeted byte-level variants of one protocol field, grounded in a real example value.",
        prompt,
    )


def generate_coverage_gap_variants(
    model: str,
    base_url: str,
    compiler_binary: Path,
    parser_name: str,
    base_seed: bytes,
    ie_name: str,
    current_value_hex: str,
    count: int,
) -> tuple[list[bytes], list[str]]:
    """Phase 3.2: ask the model for `count` replacement values for one IE
    already known to be present in base_seed, splice each candidate in via
    the base_hex/replace_ie_value compiler path, and return only the ones
    that compile to a well-formed result. Never raises on a bad model
    suggestion; every rejection is returned as a message, not swallowed.
    """
    message_type = MESSAGE_TYPE_BY_PARSER[parser_name]
    if ie_name not in MUTABLE_IES[message_type]:
        raise ValueError(f"unsupported IE {ie_name!r} for {message_type}")
    text = _request_coverage_gap_variants(model, base_url, parser_name, ie_name, current_value_hex, count)
    errors: list[str] = []
    try:
        payload = json.loads(text)
        candidates = payload.get("value_hex_variants") if isinstance(payload, dict) else None
        if not isinstance(candidates, list):
            raise ValueError("expected a JSON array under value_hex_variants")
    except (json.JSONDecodeError, ValueError) as exc:
        return [], [f"could not parse model output: {exc}"]

    specs = []
    for candidate in candidates:
        if not isinstance(candidate, str):
            errors.append(f"skipped non-string candidate: {candidate!r}")
            continue
        specs.append({
            "parser": parser_name, "message_type": message_type, "archetype": "coverage_gap",
            "base_hex": base_seed.hex(), "fields": {},
            "mutations": [{"op": "replace_ie_value", "ie": ie_name, "value_hex": candidate}],
        })
    variants: list[bytes] = []
    for seed, error in _compile_specs(compiler_binary, specs):
        if error:
            errors.append(error)
            continue
        variants.append(seed)
    return variants, errors


def validate_and_merge_frontier_seeds(
    afl_showmap: Path,
    binary: Path,
    parser_name: str,
    queue_dir: Path,
    candidates: list[bytes],
    output_corpus: Path,
    timeout_ms: int = 1000,
    memory_mb: int = 2048,
    baseline_repeats: int = 2,
    candidate_repeats: int = 3,
) -> dict[str, Any]:
    """Phase 3.3: locally confirm each candidate hits an edge not already in
    the existing queue's union coverage (via afl-showmap, the same tool
    AFL++'s own corpus-minimization tooling relies on) before writing it into
    a round-2 corpus. Candidates that add nothing are recorded as rejected,
    never silently dropped.

    QEMU-mode instrumentation retains non-trivial residual non-determinism
    even after the Phase 2 hardening (measured AFL stability ~98-99%, never
    exactly 100%). Direct measurement for this function confirmed repeat
    showmap runs on a byte-identical input can disagree on dozens of edge IDs
    (not just one or two) out of ~65536 map slots. Two asymmetric mitigations
    are applied to keep that noise from corrupting accept/reject decisions:
      - the baseline (existing queue coverage) is measured `baseline_repeats`
        times and the UNION is used, so a flaky edge that a baseline run
        happened to miss is still treated as "already covered";
      - each candidate is measured `candidate_repeats` times and only edges
        that are new (vs. the baseline) in EVERY repeat are counted as
        confirmed new coverage, so a flaky one-off edge on the candidate
        side cannot trigger a false accept.
    This does not eliminate noise, only reduces its practical impact; the
    returned report records raw per-repeat edge counts for transparency.
    """
    env = os.environ.copy()
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["GOMAXPROCS"] = "1"
    env["GOGC"] = "off"
    env["GODEBUG"] = "asyncpreemptoff=1,gctrace=0"
    code_range = _resolve_nas_code_range(binary)
    if code_range is not None:
        env["AFL_CODE_START"], env["AFL_CODE_END"] = code_range
    test_module = ROOT / "vendor" / "free5gc" / "test"

    def measure_edges(map_path: Path, *, input_dir: Path) -> tuple[set[str] | None, str]:
        # -C/-i is used for BOTH baseline and candidate measurement (never -f)
        # because afl-showmap's single-file -f mode uses a different hit-count
        # bucketing scheme than -C/-i, which was confirmed (via direct testing)
        # to produce a spurious, deterministic "new edge" for a byte-identical
        # candidate purely from the mode mismatch -- not genuine coverage gain.
        command = [str(afl_showmap), "-Q", "-C", "-t", str(timeout_ms), "-m", str(memory_mb),
                   "-i", str(input_dir), "-o", str(map_path), "--", str(binary), parser_name, "@@"]
        result = subprocess.run(command, cwd=test_module, env=env, check=False, capture_output=True, text=True)
        if result.returncode != 0 or not map_path.exists():
            return None, f"afl-showmap failed: {result.stderr.strip()[-300:]}"
        edges = {line.split(":", 1)[0] for line in map_path.read_text().splitlines() if line.strip()}
        return edges, ""

    with tempfile.TemporaryDirectory() as work_dir_str:
        work_dir = Path(work_dir_str)

        baseline_edges: set[str] = set()
        for repeat in range(baseline_repeats):
            edges, error = measure_edges(work_dir / f"baseline_run{repeat}.txt", input_dir=queue_dir)
            if edges is None:
                raise RuntimeError(f"baseline afl-showmap run {repeat} failed: {error}")
            baseline_edges |= edges

        accepted: list[bytes] = []
        verdicts: list[dict[str, Any]] = []
        for index, candidate in enumerate(candidates):
            candidate_dir = work_dir / f"candidate_{index:04d}_input"
            candidate_dir.mkdir()
            (candidate_dir / "candidate.bin").write_bytes(candidate)

            repeat_new_edge_sets: list[set[str]] = []
            failure: str | None = None
            for repeat in range(candidate_repeats):
                edges, error = measure_edges(
                    work_dir / f"candidate_{index:04d}_run{repeat}.txt", input_dir=candidate_dir
                )
                if edges is None:
                    failure = error
                    break
                repeat_new_edge_sets.append(edges - baseline_edges)
            if failure is not None:
                verdicts.append({
                    "index": index, "sha256": hashlib.sha256(candidate).hexdigest(),
                    "accepted": False, "reason": failure,
                })
                continue

            confirmed_new_edges = set.intersection(*repeat_new_edge_sets)
            raw_new_edge_counts = [len(edges) for edges in repeat_new_edge_sets]
            if confirmed_new_edges:
                accepted.append(candidate)
                # subsequent candidates compared against a growing frontier; only
                # fold in the confirmed edges so a flaky "extra" edge from this
                # candidate's own measurement noise doesn't mask later candidates.
                baseline_edges |= confirmed_new_edges
                verdicts.append({
                    "index": index, "sha256": hashlib.sha256(candidate).hexdigest(),
                    "accepted": True, "new_edge_count": len(confirmed_new_edges),
                    "raw_new_edge_counts_per_repeat": raw_new_edge_counts,
                })
            else:
                verdicts.append({
                    "index": index, "sha256": hashlib.sha256(candidate).hexdigest(),
                    "accepted": False, "reason": "no edges beyond existing queue coverage",
                    "raw_new_edge_counts_per_repeat": raw_new_edge_counts,
                })

    output_corpus.mkdir(parents=True, exist_ok=True)
    if any(output_corpus.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty corpus: {output_corpus}")
    for index, seed in enumerate(accepted, 1):
        (output_corpus / f"seed_{index:03d}.bin").write_bytes(seed)

    return {
        "candidate_count": len(candidates),
        "accepted_count": len(accepted),
        "baseline_repeats": baseline_repeats,
        "candidate_repeats": candidate_repeats,
        "verdicts": verdicts,
    }


def run_coverage_feedback_round(
    campaign: Path,
    queue_dir: Path,
    binary: Path,
    afl_showmap: Path,
    parser_name: str,
    model: str,
    base_url: str,
    output_corpus: Path,
    max_seeds: int = 10,
    variants_per_ie: int = 5,
    timeout_ms: int = 1000,
    memory_mb: int = 2048,
    go_binary: Path | None = None,
) -> dict[str, Any]:
    """Phase 3 end-to-end: 3.1 extract frontier seeds that unlocked new
    coverage, 3.2 ask the model for targeted variants of each mutable IE a
    frontier seed reached (grounded in that seed's real current value), and
    3.3 locally validate every variant before merging accepted ones into
    output_corpus for a second AFL++ round. Every frontier seed and every
    (seed, IE) pair is recorded in the returned manifest, including ones that
    were skipped or produced zero accepted candidates, never silently
    dropped.
    """
    compiler_binary = _build_seed_compiler(campaign, go_binary)
    message_type = MESSAGE_TYPE_BY_PARSER[parser_name]
    mutable_ies = MUTABLE_IES[message_type]

    frontier = extract_frontier_seeds(queue_dir)[:max_seeds]
    seeds = [path.read_bytes() for path in frontier]
    dissected = dissect_seeds(compiler_binary, parser_name, seeds)

    all_candidates: list[bytes] = []
    manifest_entries: list[dict[str, Any]] = []
    for path, seed_bytes, result in zip(frontier, seeds, dissected):
        if not result.get("ok"):
            manifest_entries.append({
                "seed": path.name, "skipped": True,
                "reason": f"dissect failed: {result.get('error', '')}",
            })
            continue
        ie_values = result.get("mutable_ie_values") or {}
        targets = {ie: value for ie, value in ie_values.items() if ie in mutable_ies}
        if not targets:
            manifest_entries.append({
                "seed": path.name, "skipped": True,
                "reason": "no mutable IE with a known value reached",
            })
            continue
        for ie_name, current_value_hex in targets.items():
            variants, errors = generate_coverage_gap_variants(
                model, base_url, compiler_binary, parser_name, seed_bytes,
                ie_name, current_value_hex, variants_per_ie,
            )
            all_candidates.extend(variants)
            manifest_entries.append({
                "seed": path.name, "ie": ie_name, "current_value_hex": current_value_hex,
                "candidates_compiled": len(variants), "compile_errors": errors,
            })

    validation = validate_and_merge_frontier_seeds(
        afl_showmap, binary, parser_name, queue_dir, all_candidates, output_corpus, timeout_ms, memory_mb,
    )
    return {
        "frontier_seed_count": len(frontier),
        "candidate_generation": manifest_entries,
        "validation": validation,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Matched AFL++ seed comparison for free5GC NAS parsers")
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare", help="create equal-sized ordinary and Ollama seed corpora")
    prepare.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    prepare.add_argument("--count", type=int, default=8)
    prepare.add_argument("--model", default=DEFAULT_MODEL)
    prepare.add_argument("--ollama-url", default=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))

    run = subparsers.add_parser("run", help="run matched GMM/GSM AFL++ QEMU trials sequentially")
    run.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    run.add_argument("--binary", default=None)
    run.add_argument("--afl", default=None)
    run.add_argument("--runtime", type=int, default=30)
    run.add_argument("--timeout-ms", type=int, default=1000)
    run.add_argument("--memory-mb", type=int, default=2048)
    run.add_argument("--seed", type=int, default=20261002)
    run.add_argument("--go", type=Path, default=None)

    report = subparsers.add_parser("report", help="render results.md from a completed results.json")
    report.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)

    matrix_prepare = subparsers.add_parser("prepare-matrix", help="prepare multiple model corpora and a paired repeat plan")
    matrix_prepare.add_argument("--campaign", type=Path, required=True)
    matrix_prepare.add_argument("--models", default="llama3.2:3b,qwen2.5-coder:3b")
    matrix_prepare.add_argument("--count", type=int, default=4)
    matrix_prepare.add_argument("--repeats", type=int, default=3)
    matrix_prepare.add_argument("--seed", type=int, default=20261002)
    matrix_prepare.add_argument("--ollama-url", default=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
    matrix_prepare.add_argument("--strategy", choices=("structured", "raw_hex"), default="structured")
    matrix_prepare.add_argument("--go", type=Path, default=None)

    matrix_run = subparsers.add_parser("run-matrix", help="run the prepared paired multi-model AFL++ matrix")
    matrix_run.add_argument("--campaign", type=Path, required=True)
    matrix_run.add_argument("--afl", default=None)
    matrix_run.add_argument("--go", type=Path, default=None)
    matrix_run.add_argument("--runtime", type=int, default=600)
    matrix_run.add_argument("--timeout-ms", type=int, default=1000)
    matrix_run.add_argument("--memory-mb", type=int, default=2048)
    matrix_run.add_argument("--shard-index", type=int, default=0)
    matrix_run.add_argument("--shard-count", type=int, default=1)

    repeat_check = subparsers.add_parser(
        "repeatability-check",
        help="run N identical AFL++ trials (same corpus, same AFL seed) to measure instrumentation stability",
    )
    repeat_check.add_argument("--campaign", type=Path, required=True)
    repeat_check.add_argument("--corpus", type=Path, required=True)
    repeat_check.add_argument("--parser", choices=PARSERS, required=True)
    repeat_check.add_argument("--afl", default=None)
    repeat_check.add_argument("--go", type=Path, default=None)
    repeat_check.add_argument("--runtime", type=int, default=60)
    repeat_check.add_argument("--timeout-ms", type=int, default=1000)
    repeat_check.add_argument("--memory-mb", type=int, default=2048)
    repeat_check.add_argument("--seed", type=int, default=20261002)
    repeat_check.add_argument("--repeats", type=int, default=5)

    coverage_round = subparsers.add_parser(
        "coverage-feedback-round",
        help="extract frontier seeds, request LLM coverage-gap IE variants, and validate+merge a round-2 corpus",
    )
    coverage_round.add_argument("--campaign", type=Path, required=True)
    coverage_round.add_argument("--queue", type=Path, required=True)
    coverage_round.add_argument("--binary", type=Path, required=True)
    coverage_round.add_argument("--parser", choices=PARSERS, required=True)
    coverage_round.add_argument("--output-corpus", type=Path, required=True)
    coverage_round.add_argument("--model", default=DEFAULT_MODEL)
    coverage_round.add_argument("--ollama-url", default=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
    coverage_round.add_argument("--afl-showmap", default=None)
    coverage_round.add_argument("--go", type=Path, default=None)
    coverage_round.add_argument("--max-seeds", type=int, default=10)
    coverage_round.add_argument("--variants-per-ie", type=int, default=5)
    coverage_round.add_argument("--timeout-ms", type=int, default=1000)
    coverage_round.add_argument("--memory-mb", type=int, default=2048)

    args = parser.parse_args(argv)
    campaign = args.campaign.expanduser().resolve()
    try:
        if args.command == "prepare":
            prepare_campaign(campaign, args.count, args.model, args.ollama_url)
            print(f"Prepared matched seed corpora under {campaign}")
            return 0
        if args.command == "report":
            rows = json.loads((campaign / "results.json").read_text(encoding="utf-8"))
            write_report(campaign, rows)
            print(f"Wrote report to {campaign / 'results.md'}")
            return 0
        if args.command == "prepare-matrix":
            model_names = [model.strip() for model in args.models.split(",") if model.strip()]
            prepare_model_matrix(
                campaign, model_names, args.count, args.ollama_url, args.seed, args.repeats,
                strategy=args.strategy, go_binary=args.go,
            )
            run_count = len(build_paired_run_plan(model_names, args.repeats, args.seed))
            print(f"Prepared {len(model_names)} models ({args.strategy} strategy) and {run_count} paired runs under {campaign}")
            return 0
        if args.command == "run-matrix":
            afl = _afl_binary(args.afl)
            if not afl.is_file():
                raise FileNotFoundError(f"afl-fuzz missing: {afl}")
            rows, _ = run_model_matrix(
                campaign, afl, args.runtime, args.timeout_ms, args.memory_mb, args.go,
                args.shard_index, args.shard_count,
            )
            shard_path = campaign / f"matrix_shard_{args.shard_index:02d}_results.json"
            with shard_path.open("x", encoding="utf-8") as handle:
                json.dump(rows, handle, indent=2)
                handle.write("\n")
            shard_paths = [campaign / f"matrix_shard_{index:02d}_results.json" for index in range(args.shard_count)]
            if not all(path.is_file() for path in shard_paths):
                print(f"Completed shard {args.shard_index + 1}/{args.shard_count}: {len(rows)} matched-arm runs")
                return 0
            manifest = json.loads((campaign / "matrix_manifest.json").read_text(encoding="utf-8"))
            all_rows = [row for path in shard_paths for row in json.loads(path.read_text(encoding="utf-8"))]
            plan_order = {
                (entry["model"], entry["parser"], str(entry["repeat"]), entry["arm"]): index
                for index, entry in enumerate(manifest["run_plan"])
            }
            all_rows.sort(key=lambda row: plan_order[(row["model"], row["parser"], row["repeat"], row["seed_arm"])])
            if len(all_rows) != len(manifest["run_plan"]):
                raise RuntimeError(
                    f"collected {len(all_rows)} run results for {len(manifest['run_plan'])} planned runs"
                )
            deltas = summarize_paired_rows(all_rows, manifest["models"], PARSERS, int(manifest["repeats"]))
            write_matrix_results(campaign, all_rows, deltas)
            print(f"Wrote complete multi-model results under {campaign}")
            return 0
        if args.command == "repeatability-check":
            afl = _afl_binary(args.afl)
            if not afl.is_file():
                raise FileNotFoundError(f"afl-fuzz missing: {afl}")
            rows = run_repeatability_check(
                campaign, args.corpus.expanduser().resolve(), args.parser, afl,
                args.runtime, args.timeout_ms, args.memory_mb, args.seed, args.repeats, args.go,
            )
            summary = write_repeatability_report(campaign, rows)
            status = "PASS" if summary["passed"] else "FAIL"
            print(
                f"Repeatability check {status}: min stability {summary['min_stability_percent']:.2f}%, "
                f"median {summary['median_stability_percent']:.2f}% under {campaign}"
            )
            return 0
        if args.command == "coverage-feedback-round":
            afl_showmap = _afl_showmap_binary(args.afl_showmap)
            if not afl_showmap.is_file():
                raise FileNotFoundError(f"afl-showmap missing: {afl_showmap}")
            result = run_coverage_feedback_round(
                campaign, args.queue.expanduser().resolve(), args.binary.expanduser().resolve(), afl_showmap,
                args.parser, args.model, args.ollama_url, args.output_corpus.expanduser().resolve(),
                args.max_seeds, args.variants_per_ie, args.timeout_ms, args.memory_mb, args.go,
            )
            (campaign / "coverage_feedback_round.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
            validation = result["validation"]
            print(
                f"Coverage-feedback round: {result['frontier_seed_count']} frontier seeds processed, "
                f"{validation['candidate_count']} candidates generated, {validation['accepted_count']} accepted "
                f"into {args.output_corpus}"
            )
            return 0
        afl = _afl_binary(args.afl)
        if not afl.is_file():
            raise FileNotFoundError(f"afl-fuzz missing: {afl}")
        binary = Path(args.binary).expanduser().resolve() if args.binary else None
        rows = run_comparison(campaign, binary, afl,
                              args.runtime, args.timeout_ms, args.memory_mb, args.seed, args.go)
        write_results(campaign, rows)
        print(f"Wrote matched results to {campaign / 'results.csv'}")
        return 0
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
