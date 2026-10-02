from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED_CATEGORIES = {
    "CATEGORY_VALID_DEEP",
    "CATEGORY_BOUNDARY_TLV",
    "CATEGORY_IE_PERMUTATION",
    "CATEGORY_TRUNCATED_BOUNDS",
}


def export_corpus(seed_file: Path, output_dir: Path) -> dict:
    seeds = json.loads(seed_file.read_text(encoding="utf-8"))
    if not isinstance(seeds, list) or len(seeds) != 16:
        raise ValueError("expected exactly 16 seed records")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty corpus directory: {output_dir}")

    entries = []
    seen_names = set()
    for seed in seeds:
        protocol = seed["protocol"].lower()
        category = seed["category"]
        name = seed["name"]
        if protocol not in {"gmm", "gsm"}:
            raise ValueError(f"{name}: unsupported protocol {protocol}")
        if category not in EXPECTED_CATEGORIES:
            raise ValueError(f"{name}: unsupported category {category}")
        if name in seen_names:
            raise ValueError(f"duplicate seed name: {name}")
        seen_names.add(name)
        raw = seed["hex"]
        if len(raw) % 2:
            raise ValueError(f"{name}: odd-length hex")
        payload = bytes.fromhex(raw)
        if not payload or len(payload) > 4096:
            raise ValueError(f"{name}: size outside 1..4096 bytes")
        target = output_dir / protocol / f"{category.lower()}__{name}.bin"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        entries.append(
            {
                "name": name,
                "protocol": protocol.upper(),
                "category": category,
                "path": str(target.relative_to(output_dir)),
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )

    manifest = {"schema_version": "nas-curated-corpus-v1", "input_seed_file": str(seed_file), "seeds": entries}
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Export validated NAS seed records into protocol-separated AFL corpora")
    parser.add_argument("--seeds", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifest = export_corpus(args.seeds.resolve(), args.out.resolve())
    print(f"Exported {len(manifest['seeds'])} seeds into {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
