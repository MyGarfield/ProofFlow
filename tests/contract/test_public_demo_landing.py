from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_public_demo_landing import validate_public_demo  # noqa: E402

SITE_ROOT = ROOT / "public-demo"


def _copy_site(tmp_path: Path) -> Path:
    copied = tmp_path / "public-demo"
    shutil.copytree(SITE_ROOT, copied)
    return copied


def test_public_demo_landing_passes_closed_static_contract() -> None:
    assert validate_public_demo(ROOT, SITE_ROOT) == []


def test_validator_rejects_remote_loaded_script(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    index_path = copied / "index.html"
    html = index_path.read_text(encoding="utf-8")
    index_path.write_text(
        html.replace("./app.js", "https://cdn.example.invalid/app.js", 1),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("loaded resource script[src] must be path-relative" in item for item in errors)


def test_validator_rejects_false_live_worker_claim(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    index_path = copied / "index.html"
    html = index_path.read_text(encoding="utf-8")
    index_path.write_text(
        html.replace("</footer>", "<p>Workers Running / readyWorkers=6</p></footer>"),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("forbidden visible claim" in item for item in errors)


def test_validator_rejects_broken_relative_link(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    index_path = copied / "index.html"
    html = index_path.read_text(encoding="utf-8")
    index_path.write_text(
        html.replace('href="./README.md"', 'href="./MISSING.md"', 1),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("local anchor target is missing" in item for item in errors)


def test_validator_rejects_unbacked_published_video_claim(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    contract_path = copied / "media/video-contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["publication_status"] = "PUBLISHED"
    contract_path.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("video must remain NOT_PUBLISHED" in item for item in errors)


def test_validator_rejects_public_artifact_hash_drift(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    evidence_path = copied / "evidence-snapshot.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["public_artifacts"][0]["sha256"] = "0" * 64
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("public artifact hash mismatch" in item for item in errors)


def test_validator_rejects_css_generated_overclaim(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    styles_path = copied / "styles.css"
    styles_path.write_text(
        styles_path.read_text(encoding="utf-8")
        + '\n.brand::after { content: "Workers Running"; }\n',
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("forbidden claim token in loaded asset styles.css" in item for item in errors)


def test_validator_requires_exact_fixed_material_links(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    index_path = copied / "index.html"
    html = index_path.read_text(encoding="utf-8")
    index_path.write_text(
        html.replace(
            "/submission/public/ProofFlow_GOAI_%E5%A4%8D%E8%B5%9B%E7%AD%94%E8%BE%A9_v2.0.pdf",
            "/README.md",
            1,
        ),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("exact reviewed GitHub closed set" in item for item in errors)


def test_validator_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    contract_path = copied / "media/video-contract.json"
    contract = contract_path.read_text(encoding="utf-8")
    contract_path.write_text(
        contract.replace(
            '"publication_status": "NOT_PUBLISHED",',
            '"publication_status": "NOT_PUBLISHED",\n  "publication_status": "PUBLISHED",',
            1,
        ),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("duplicate JSON key" in item for item in errors)
