from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.validate_public_demo_landing import validate_public_demo  # noqa: E402

SITE_ROOT = ROOT / "public-demo"


def _copy_site(tmp_path: Path) -> Path:
    copied = tmp_path / "public-demo"
    shutil.copytree(SITE_ROOT, copied)
    return copied


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_public_demo_landing_passes_closed_static_contract() -> None:
    assert validate_public_demo(ROOT, SITE_ROOT) == []


def test_ci_checkout_fetches_complete_fixed_baseline_history() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    checkout_steps = [
        step
        for step in workflow["jobs"]["contracts"]["steps"]
        if step.get("uses") == "actions/checkout@v4"
    ]

    assert len(checkout_steps) == 1
    assert checkout_steps[0]["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
    }


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


def test_validator_rejects_removal_of_historical_snapshot_boundary(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    index_path = copied / "index.html"
    html = index_path.read_text(encoding="utf-8")
    index_path.write_text(
        html.replace("不代表当前 Core alpha", "当前产品", 1),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any(
        "required visible claim boundary is missing: 不代表当前 Core alpha" in item
        for item in errors
    )


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


@pytest.mark.parametrize(
    "claim",
    ("Workers Running", "LLM ON", "OFFICIAL SCORE: 100"),
)
@pytest.mark.parametrize(
    "surface",
    ("evidence-snapshot.json", "media/video-contract.json", "README.md"),
)
def test_validator_rejects_overclaims_in_every_non_html_claim_surface(
    tmp_path: Path,
    surface: str,
    claim: str,
) -> None:
    copied = _copy_site(tmp_path)
    target = copied / surface
    if surface == "evidence-snapshot.json":
        value = json.loads(target.read_text(encoding="utf-8"))
        value["digest_disclaimer"] += f" {claim}"
        _write_json(target, value)
    elif surface == "media/video-contract.json":
        value = json.loads(target.read_text(encoding="utf-8"))
        value["publication_gate"][0] += f" {claim}"
        _write_json(target, value)
    else:
        target.write_text(
            target.read_text(encoding="utf-8") + f"\n{claim}\n",
            encoding="utf-8",
        )

    errors = validate_public_demo(ROOT, copied)

    assert any(
        "forbidden claim token" in item and surface.split("/")[-1] in item for item in errors
    )


@pytest.mark.parametrize(
    ("surface", "object_path"),
    (
        ("evidence-snapshot.json", ()),
        ("evidence-snapshot.json", ("source",)),
        ("evidence-snapshot.json", ("reference_flow", 0)),
        ("evidence-snapshot.json", ("public_artifacts", 0)),
        ("media/video-contract.json", ()),
        ("media/video-contract.json", ("subtitles",)),
        ("media/video-contract.json", ("claim_boundaries",)),
    ),
)
def test_validator_rejects_nested_and_array_item_extra_fields(
    tmp_path: Path,
    surface: str,
    object_path: tuple[str | int, ...],
) -> None:
    copied = _copy_site(tmp_path)
    target = copied / surface
    value = json.loads(target.read_text(encoding="utf-8"))
    nested = value
    for segment in object_path:
        nested = nested[segment]
    nested["unreviewed"] = "extra"
    _write_json(target, value)

    errors = validate_public_demo(ROOT, copied)

    assert any(
        "exact-key shape mismatch" in item and "unexpected=unreviewed" in item for item in errors
    )


@pytest.mark.parametrize(
    ("surface", "sensitive_value"),
    (
        ("README.md", "contact 13800138000"),
        ("README.md", "~/private-case.json"),
        ("README.md", r"\\server\share\private-case.json"),
        ("evidence-snapshot.json", "/Users/example/private-case.json"),
        ("media/video-contract.json", "api_key=examplecredential123"),
        ("media/proofflow-reference-demo.zh-CN.vtt", "contact person@example.com"),
    ),
)
def test_validator_rejects_privacy_secret_and_machine_path_leaks(
    tmp_path: Path,
    surface: str,
    sensitive_value: str,
) -> None:
    copied = _copy_site(tmp_path)
    target = copied / surface
    if surface == "evidence-snapshot.json":
        value = json.loads(target.read_text(encoding="utf-8"))
        value["digest_disclaimer"] += f" {sensitive_value}"
        _write_json(target, value)
    elif surface == "media/video-contract.json":
        value = json.loads(target.read_text(encoding="utf-8"))
        value["publication_gate"][0] += f" {sensitive_value}"
        _write_json(target, value)
    else:
        target.write_text(
            target.read_text(encoding="utf-8") + f"\n{sensitive_value}\n",
            encoding="utf-8",
        )

    errors = validate_public_demo(ROOT, copied)

    assert any("sensitive " in item and surface.split("/")[-1] in item for item in errors)


@pytest.mark.parametrize(
    "rendered_overclaim",
    (
        "Workers&#32;Running",
        "Workers <span>Running</span>",
        "L&#76;M <em>ON</em>",
        "OFFICIAL **SCORE**: 100",
    ),
)
def test_validator_rejects_markup_obfuscated_readme_overclaims(
    tmp_path: Path,
    rendered_overclaim: str,
) -> None:
    copied = _copy_site(tmp_path)
    readme_path = copied / "README.md"
    readme_path.write_text(
        readme_path.read_text(encoding="utf-8") + f"\n{rendered_overclaim}\n",
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("forbidden claim token in loaded asset README.md" in item for item in errors)


@pytest.mark.parametrize(
    "credential",
    (
        "client_secret=examplecredential123",
        "secret_key: examplecredential123",
        "auth-token=examplecredential123",
        "refresh_token=examplecredential123",
        "PROOFFLOW_API_KEY=examplecredential123",
        "DB_PASSWORD=examplecredential123",
        "AWS_SECRET_ACCESS_KEY=examplecredential123",
        "GITHUB_TOKEN=examplecredential123",
    ),
)
def test_validator_rejects_common_assigned_credentials_in_readme(
    tmp_path: Path,
    credential: str,
) -> None:
    copied = _copy_site(tmp_path)
    readme_path = copied / "README.md"
    readme_path.write_text(
        readme_path.read_text(encoding="utf-8") + f"\n{credential}\n",
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("sensitive assigned credential in loaded asset README.md" in item for item in errors)
