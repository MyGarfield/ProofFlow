from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_public_demo_snapshot import (  # noqa: E402
    SOURCE_COMMIT,
    SOURCE_TREE,
    SnapshotGenerationError,
    build_snapshot,
    serialize_snapshot,
)
from scripts.validate_public_demo_landing import (  # noqa: E402
    EXPECTED_ACTION_PINS,
    LANDING_CHECK_COMMAND,
    SNAPSHOT_CHECK_COMMAND,
    _validate_pages_workflow,
    validate_public_demo,
)

SITE_ROOT = ROOT / "public-demo"


def _copy_site(tmp_path: Path) -> Path:
    copied = tmp_path / "public-demo"
    shutil.copytree(SITE_ROOT, copied)
    return copied


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def test_current_public_demo_passes_source_bound_static_contract() -> None:
    assert validate_public_demo(ROOT, SITE_ROOT) == []


def test_snapshot_is_exact_deterministic_git_object_derivation() -> None:
    snapshot = build_snapshot(ROOT, source_commit=SOURCE_COMMIT)

    assert (SITE_ROOT / "evidence-snapshot.json").read_bytes() == serialize_snapshot(snapshot)
    assert snapshot["source"]["commit"] == SOURCE_COMMIT
    assert snapshot["source"]["tree"] == SOURCE_TREE
    assert snapshot["landing"]["included_in_source_commit"] is False
    assert snapshot["landing"]["self_authenticating"] is False
    assert snapshot["current_core"]["test_counts"] == {
        "full_repo_provenance": "PINNED_MAIN_CI_DECLARATION",
        "full_repo_ci_run_id": 33213175597,
        "full_repo_ci_run_url": (
            "https://github.com/MyGarfield/ProofFlow/actions/runs/33213175597"
        ),
        "full_repo_ci_head_sha": SOURCE_COMMIT,
        "full_repo_total": 610,
        "full_repo_passed": 609,
        "full_repo_skipped": 1,
        "source_readme_declared_full_repo_passed": 569,
        "action_certificate_provenance": "SOURCE_README_DECLARATION",
        "action_certificate_passed": 53,
        "generator_executed_tests": False,
    }


def test_snapshot_generator_rejects_unreviewed_source_commit() -> None:
    with pytest.raises(SnapshotGenerationError, match="outside the reviewed snapshot contract"):
        build_snapshot(ROOT, source_commit="b63eeb60d1072c73d2d0d1d6061b3c8f800487a4")


def test_product_asset_records_match_pinned_git_blobs() -> None:
    snapshot = build_snapshot(ROOT)
    records = snapshot["product_assets"]["entries"]
    assert len(records) == 19
    assert {record["path"] for record in records} >= {
        ".github/workflows/release-supply-chain-evidence.yml",
        "deploy/tool-service/evidence/supply-chain-evidence.schema.json",
        "deploy/tool-service/evidence/supply-chain-release-policy.schema.json",
        "deploy/tool-service/scripts/collect_supply_chain_evidence.py",
        "deploy/tool-service/scripts/validate_supply_chain_evidence.py",
    }
    assert snapshot["supply_chain_boundary"] == {
        "status": "STALE",
        "historical_snapshot_only": True,
        "release_eligible": False,
        "fresh_build_scan_and_provenance_required": True,
        "freshness_release_gate_implemented": True,
        "release_policy_schema_bound": True,
        "release_workflow_is_disabled_design": True,
    }
    for record in records:
        blob = subprocess.run(
            ["git", "cat-file", "blob", f"{SOURCE_COMMIT}:{record['path']}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        assert len(blob) == record["bytes"]


def test_pages_workflow_is_static_main_only_and_full_sha_pinned() -> None:
    workflow = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")

    assert _validate_pages_workflow(ROOT) == []
    assert all(len(pin.rsplit("@", maxsplit=1)[1]) == 40 for pin in EXPECTED_ACTION_PINS)
    assert workflow.count("if: github.ref == 'refs/heads/main'") == 2
    assert "path: ./public-demo" in workflow
    assert "persist-credentials: false" in workflow


def test_public_demo_readme_uses_exact_locked_uv_commands() -> None:
    readme = (SITE_ROOT / "README.md").read_text(encoding="utf-8")
    unfolded = readme.replace("\\\n  ", "")

    assert "python3 scripts/generate_public_demo_snapshot.py" not in readme
    assert "python3 scripts/validate_public_demo_landing.py" not in readme
    assert SNAPSHOT_CHECK_COMMAND in unfolded
    assert LANDING_CHECK_COMMAND in unfolded
    assert "从仓库根目录运行" in readme
    assert "已提交的 `uv.lock`" in readme


def test_validator_rejects_removed_current_snapshot_boundary(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    index = copied / "index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace("CURRENT CORE ALPHA SNAPSHOT", "CORE PAGE"),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("CURRENT CORE ALPHA SNAPSHOT" in error for error in errors)


@pytest.mark.parametrize("surface", ("index.html", "evidence-snapshot.json"))
def test_validator_rejects_source_commit_substitution(tmp_path: Path, surface: str) -> None:
    copied = _copy_site(tmp_path)
    target = copied / surface
    target.write_text(
        target.read_text(encoding="utf-8").replace(SOURCE_COMMIT, "0" * 40, 1),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("source commit" in error or ".source.commit" in error for error in errors)


@pytest.mark.parametrize(
    "claim",
    (
        "Workers Running",
        "readyWorkers=6",
        "LLM ON",
        "OFFICIAL SCORE: 100",
        "SUPPLY EVIDENCE FRESH",
        "ExecutionReceipt IMPLEMENTED",
        "OutcomeClosure READY",
    ),
)
def test_validator_rejects_visible_overclaims(tmp_path: Path, claim: str) -> None:
    copied = _copy_site(tmp_path)
    index = copied / "index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace("</footer>", f"<p>{claim}</p></footer>"),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("forbidden claim token" in error for error in errors)


@pytest.mark.parametrize(
    "claim",
    (
        "Workers&#32;Running",
        "Workers <span>Running</span>",
        "L&#76;M <em>ON</em>",
        "OFFICIAL **SCORE**: 100",
    ),
)
def test_validator_rejects_markup_obfuscated_overclaims(tmp_path: Path, claim: str) -> None:
    copied = _copy_site(tmp_path)
    readme = copied / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + f"\n{claim}\n", encoding="utf-8")

    errors = validate_public_demo(ROOT, copied)

    assert any("forbidden claim token" in error for error in errors)


def test_validator_rejects_remote_loaded_script(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    index = copied / "index.html"
    index.write_text(
        index.read_text(encoding="utf-8").replace(
            "./app.js", "https://cdn.example.invalid/app.js", 1
        ),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("loaded resources" in error or "must be path-relative" in error for error in errors)


def test_validator_rejects_remote_css_resource(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    styles = copied / "styles.css"
    styles.write_text(
        styles.read_text(encoding="utf-8")
        + "\n.remote { background-image: url(https://example.invalid/pixel.png); }\n",
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("CSS contains forbidden" in error for error in errors)


@pytest.mark.parametrize(
    "path",
    (
        (),
        ("source",),
        ("current_core", "action_certificate"),
        ("product_assets", "entries", 0),
        ("fixture_bundle", "entries", 0),
        ("non_claims",),
    ),
)
def test_validator_rejects_json_extra_fields(tmp_path: Path, path: tuple[str | int, ...]) -> None:
    copied = _copy_site(tmp_path)
    target = copied / "evidence-snapshot.json"
    snapshot = json.loads(target.read_text(encoding="utf-8"))
    nested = snapshot
    for segment in path:
        nested = nested[segment]
    nested["unreviewed"] = "extra"
    _write_json(target, snapshot)

    errors = validate_public_demo(ROOT, copied)

    assert any(
        "exact-key shape mismatch" in error and "unexpected=unreviewed" in error for error in errors
    )


def test_validator_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    target = copied / "evidence-snapshot.json"
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            '"schema_version": "2.0",',
            '"schema_version": "2.0",\n  "schema_version": "9.9",',
            1,
        ),
        encoding="utf-8",
    )

    errors = validate_public_demo(ROOT, copied)

    assert any("duplicate JSON key" in error for error in errors)


def test_validator_rejects_forged_release_boolean(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    target = copied / "evidence-snapshot.json"
    snapshot = json.loads(target.read_text(encoding="utf-8"))
    snapshot["supply_chain_boundary"]["release_eligible"] = True
    _write_json(target, snapshot)

    errors = validate_public_demo(ROOT, copied)

    assert any("release_eligible" in error for error in errors)


@pytest.mark.parametrize(
    ("surface", "leak"),
    (
        ("README.md", "contact 13800138000"),
        ("README.md", "~/private-case.json"),
        ("README.md", r"\\server\share\private-case.json"),
        ("index.html", "/Users/example/private-case.json"),
        ("styles.css", "/* person@example.com */"),
        ("app.js", "// api_key=examplecredential123"),
    ),
)
def test_validator_rejects_privacy_credential_and_machine_path_leaks(
    tmp_path: Path, surface: str, leak: str
) -> None:
    copied = _copy_site(tmp_path)
    target = copied / surface
    target.write_text(target.read_text(encoding="utf-8") + f"\n{leak}\n", encoding="utf-8")

    errors = validate_public_demo(ROOT, copied)

    assert any("sensitive " in error and surface in error for error in errors)


@pytest.mark.parametrize(
    "credential",
    (
        "client_secret=examplecredential123",
        "auth-token=examplecredential123",
        "refresh_token=examplecredential123",
        "PROOFFLOW_API_KEY=examplecredential123",
        "DB_PASSWORD=examplecredential123",
        "GITHUB_TOKEN=examplecredential123",
    ),
)
def test_validator_rejects_assigned_credentials(tmp_path: Path, credential: str) -> None:
    copied = _copy_site(tmp_path)
    readme = copied / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + f"\n{credential}\n", encoding="utf-8")

    errors = validate_public_demo(ROOT, copied)

    assert any("sensitive assigned credential" in error for error in errors)


def test_validator_rejects_unexpected_static_file(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    (copied / "debug.txt").write_text("debug", encoding="utf-8")

    errors = validate_public_demo(ROOT, copied)

    assert any("static artifact closed set mismatch" in error for error in errors)


def test_validator_rejects_symlinked_static_file(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    styles = copied / "styles.css"
    styles.unlink()
    styles.symlink_to(copied / "README.md")

    errors = validate_public_demo(ROOT, copied)

    assert any("must not contain symlinks" in error for error in errors)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    (
        (
            "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
            "actions/checkout@v4",
            "ordered full-SHA closed set",
        ),
        ("path: ./public-demo", "path: .", "structure must exactly match"),
        ('version: "0.11.28"', 'version: "0.11.29"', "structure must exactly match"),
        (
            "persist-credentials: false",
            "persist-credentials: true",
            "structure must exactly match",
        ),
    ),
)
def test_pages_workflow_validator_rejects_capability_drift(
    tmp_path: Path, old: str, new: str, message: str
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    (workflow_dir / "pages.yml").write_text(source.replace(old, new, 1), encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert any(message in error for error in errors)


def test_pages_workflow_rejects_build_write_and_residual_deploy_read(
    tmp_path: Path,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    attacked = source.replace(
        "  build:\n    if: github.ref == 'refs/heads/main'\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: read\n",
        "  build:\n    if: github.ref == 'refs/heads/main'\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      contents: write\n",
        1,
    ).replace(
        "    permissions:\n      pages: write\n      id-token: write\n",
        "    permissions:\n      contents: read\n      pages: write\n      id-token: write\n",
        1,
    )
    (workflow_dir / "pages.yml").write_text(attacked, encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert any("build permissions must be exactly contents: read" in error for error in errors)
    assert any("deploy permissions must be exactly" in error for error in errors)


def test_pages_workflow_rejects_deploy_issues_write(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    attacked = source.replace(
        "      pages: write\n      id-token: write",
        "      pages: write\n      id-token: write\n      issues: write",
        1,
    )
    (workflow_dir / "pages.yml").write_text(attacked, encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert any("deploy permissions must be exactly" in error for error in errors)


def test_pages_workflow_rejects_duplicate_build_permissions_even_when_last_is_safe(
    tmp_path: Path,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    attacked = source.replace(
        "    permissions:\n      contents: read\n    steps:",
        "    permissions:\n      contents: write\n"
        "    permissions:\n      contents: read\n    steps:",
        1,
    )
    (workflow_dir / "pages.yml").write_text(attacked, encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert errors == ["Pages workflow contains duplicate YAML mapping keys"]


def test_pages_workflow_rejects_nested_duplicate_key_even_when_last_is_safe(
    tmp_path: Path,
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    attacked = source.replace(
        "          fetch-depth: 0",
        "          fetch-depth: 1\n          fetch-depth: 0",
        1,
    )
    (workflow_dir / "pages.yml").write_text(attacked, encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert errors == ["Pages workflow contains duplicate YAML mapping keys"]


def test_pages_workflow_rejects_arbitrary_deploy_run_step(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    attacked = source.replace(
        "        uses: actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e\n",
        "        uses: actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e\n"
        "      - name: Arbitrary post-deploy command\n"
        "        run: echo unexpected\n",
        1,
    )
    (workflow_dir / "pages.yml").write_text(attacked, encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert any("run commands must be the exact ordered" in error for error in errors)


@pytest.mark.parametrize(
    ("old", "new"),
    (
        (
            "    permissions:\n      contents: read\n    steps:",
            "    permissions:\n      contents: read\n    env:\n      MODE: unsafe\n    steps:",
        ),
        (
            "      - name: Verify source-bound public snapshot",
            "      - name: Extra action\n"
            "        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803\n"
            "      - name: Verify source-bound public snapshot",
        ),
        (
            "          --expected-source-commit " + SOURCE_COMMIT,
            "          --expected-source-commit "
            + SOURCE_COMMIT
            + "\n        env:\n          MODE: unsafe",
        ),
        (
            "          path: ./public-demo",
            "          path: ./public-demo\n          include-hidden-files: true",
        ),
        ("  group: pages", "  group: pages-drift"),
        ("    needs: build", "    needs: [build, audit]"),
        ("      name: github-pages", "      name: unreviewed-environment"),
    ),
)
def test_pages_workflow_rejects_extra_env_action_step_and_topology_drift(
    tmp_path: Path, old: str, new: str
) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    assert old in source
    (workflow_dir / "pages.yml").write_text(source.replace(old, new, 1), encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert any("exact" in error for error in errors)


def test_pages_workflow_validator_rejects_secret_reference(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    source = (ROOT / ".github/workflows/pages.yml").read_text(encoding="utf-8")
    (workflow_dir / "pages.yml").write_text(source + "\n# secrets.DEPLOY_TOKEN\n", encoding="utf-8")

    errors = _validate_pages_workflow(tmp_path)

    assert any("forbidden deployment capability: secrets." in error for error in errors)


def test_optimized_python_still_rejects_snapshot_attack(tmp_path: Path) -> None:
    copied = _copy_site(tmp_path)
    snapshot_path = copied / "evidence-snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    snapshot["runtime_boundary"]["readyWorkers"] = 6
    _write_json(snapshot_path, snapshot)

    result = subprocess.run(
        [
            sys.executable,
            "-O",
            "scripts/validate_public_demo_landing.py",
            "--site-root",
            str(copied),
            "--expected-source-commit",
            SOURCE_COMMIT,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "PUBLIC_DEMO_INVALID" in result.stdout
