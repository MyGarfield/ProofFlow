from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import venv
import warnings
import zipfile
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).parents[2]
BUILD_SCRIPT = ROOT / "scripts/build_installable_distribution.py"
VERSION = "0.1.0a0"


def _clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "PYTHONHOME",
        "PYTHONPATH",
        "UV_PROJECT_ENVIRONMENT",
        "VIRTUAL_ENV",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return environment


def _run(
    command: list[str],
    *,
    cwd: Path,
    expected_returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=_clean_environment(),
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == expected_returncode, (
        completed.stdout,
        completed.stderr,
    )
    return completed


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("installable_builder", BUILD_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _create_clean_package_repo(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    for filename in ("LICENSE", "NOTICE", "README.md", "pyproject.toml"):
        shutil.copy2(ROOT / filename, repository / filename)
    shutil.copytree(
        ROOT / "src/proofflow",
        repository / "src/proofflow",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    _run(["git", "init", "--quiet"], cwd=repository)
    _run(["git", "config", "user.name", "ProofFlow Test"], cwd=repository)
    _run(["git", "config", "user.email", "test@example.invalid"], cwd=repository)
    _run(["git", "add", "LICENSE", "NOTICE", "README.md", "pyproject.toml", "src"], cwd=repository)
    _run(["git", "commit", "--quiet", "-m", "test snapshot"], cwd=repository)
    assert _run(["git", "status", "--porcelain"], cwd=repository).stdout == ""
    return repository


@pytest.fixture(scope="session")
def built_distribution(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    workspace = tmp_path_factory.mktemp("installable-distribution")
    output = workspace / "dist"
    completed = _run(
        [sys.executable, str(BUILD_SCRIPT), "--output", str(output)],
        cwd=workspace,
    )
    manifest = json.loads(completed.stdout)
    manifest["_output"] = output
    return manifest


def _artifact(manifest: dict[str, Any], suffix: str) -> Path:
    records = [record for record in manifest["artifacts"] if record["filename"].endswith(suffix)]
    assert len(records) == 1
    path = manifest["_output"] / records[0]["filename"]
    assert path.is_file()
    assert _sha256(path) == records[0]["sha256"]
    assert path.stat().st_size == records[0]["bytes"]
    return path


def _safe_extract_sdist(archive: Path, output: Path) -> Path:
    with tarfile.open(archive, mode="r:gz") as source:
        members = source.getmembers()
        assert members
        for member in members:
            path = PurePosixPath(member.name)
            assert not path.is_absolute()
            assert ".." not in path.parts
            assert not member.issym()
            assert not member.islnk()
        source.extractall(output, filter="data")
    roots = [candidate for candidate in output.iterdir() if candidate.is_dir()]
    assert len(roots) == 1
    extracted = roots[0]
    assert not any(path.name == ".git" for path in extracted.rglob(".git"))
    return extracted


def _attacked_wheel_payload(wheel: Path, attack: str) -> bytes:
    output = io.BytesIO()
    with (
        zipfile.ZipFile(wheel) as source,
        zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as destination,
    ):
        for info in source.infolist():
            payload = source.read(info.filename)
            if attack == "record-tamper" and info.filename.endswith(".dist-info/RECORD"):
                payload = payload.replace(b",sha256=", b",sha256=INVALID", 1)
            destination.writestr(info, payload)
        additions = {
            "extra-pth": ("proof_flow_unexpected.pth", b"import proof_flow_unexpected\n"),
            "top-level-package": ("unexpected_package/__init__.py", b"INJECTED = True\n"),
            "second-dist-info": ("unexpected-1.0.dist-info/METADATA", b"Name: unexpected\n"),
            "path-escape": ("../proof_flow_escape.py", b"raise RuntimeError\n"),
        }
        if attack in additions:
            destination.writestr(*additions[attack])
        elif attack == "duplicate-member":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                destination.writestr("proofflow/__init__.py", b"DUPLICATE = True\n")
        elif attack != "record-tamper":
            raise AssertionError(f"unsupported wheel attack: {attack}")
    return output.getvalue()


def _venv_executables(environment_dir: Path) -> tuple[Path, Path]:
    scripts = environment_dir / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    proofflow = scripts / ("proofflow.exe" if os.name == "nt" else "proofflow")
    return python, proofflow


def _installed_journey(install_source: Path, workspace: Path) -> None:
    environment_dir = workspace / "venv"
    empty_workdir = workspace / "empty"
    empty_workdir.mkdir(parents=True)
    venv.EnvBuilder(with_pip=True, clear=True).create(environment_dir)
    python, proofflow = _venv_executables(environment_dir)
    _run(
        [str(python), "-m", "pip", "install", str(install_source)],
        cwd=empty_workdir,
    )
    installed_versions = json.loads(
        _run(
            [
                str(python),
                "-c",
                (
                    "import json; from importlib.metadata import version; "
                    "print(json.dumps({'cryptography': version('cryptography'), "
                    "'pydantic': version('pydantic')}))"
                ),
            ],
            cwd=empty_workdir,
        ).stdout
    )
    expected_cryptography = os.environ.get("PROOFFLOW_EXPECT_CRYPTOGRAPHY")
    expected_pydantic = os.environ.get("PROOFFLOW_EXPECT_PYDANTIC")
    if expected_cryptography is not None:
        assert installed_versions["cryptography"] == expected_cryptography
    if expected_pydantic is not None:
        assert installed_versions["pydantic"] == expected_pydantic

    version = _run([str(proofflow), "--version"], cwd=empty_workdir)
    assert version.stdout.strip() == f"proofflow {VERSION}"
    assert version.stderr == ""

    demo = empty_workdir / "demo"
    initialized = _run(
        [str(proofflow), "init-demo", "--output", "demo"],
        cwd=empty_workdir,
    )
    receipt = json.loads(initialized.stdout)
    assert receipt["classification"] == "PUBLIC_SYNTHETIC"
    assert receipt["output"] == "demo"
    assert receipt["status"] == "INITIALIZED"

    overwrite = _run(
        [str(proofflow), "init-demo", "--output", "demo"],
        cwd=empty_workdir,
        expected_returncode=2,
    )
    assert json.loads(overwrite.stderr)["error"]["code"] == "DEMO_OUTPUT_EXISTS"

    missing = _run(
        [
            str(proofflow),
            "prepare",
            "--manifest",
            "missing.json",
            "--rules",
            "missing-rules.json",
            "--run-dir",
            "missing-run",
        ],
        cwd=empty_workdir,
        expected_returncode=2,
    )
    missing_error = json.loads(missing.stderr)
    assert missing_error["error"]["code"] == "FILESYSTEM_ERROR"
    combined_error = missing.stdout + missing.stderr
    assert "Traceback" not in combined_error
    assert str(ROOT) not in combined_error
    assert "/Users/" not in combined_error
    assert "Documents/Codex/" not in combined_error

    prepared = _run(
        [
            str(proofflow),
            "prepare",
            "--manifest",
            "case/manifest.json",
            "--rules",
            "rules/cn_labor_contract_law.catalog.json",
            "--run-dir",
            "run",
        ],
        cwd=demo,
    )
    assert json.loads(prepared.stdout)["stage"] == "AWAITING_APPROVAL"
    approved = _run(
        [
            str(proofflow),
            "approve",
            "--run-dir",
            "run",
            "--approver-id",
            "synthetic-reviewer",
            "--role",
            "legal-reviewer",
            "--decision",
            "APPROVE",
            "--reason",
            "Reviewed the synthetic evidence, rules, calculation, risks, and uncertainties.",
        ],
        cwd=demo,
    )
    assert json.loads(approved.stdout)["decision"] == "APPROVE"
    _run([str(proofflow), "package", "--run-dir", "run"], cwd=demo)
    verified = _run([str(proofflow), "verify", "--run-dir", "run"], cwd=demo)
    assert json.loads(verified.stdout)["valid"] is True


def test_candidate_manifest_binds_hashes_and_reproducible_artifacts(
    built_distribution: dict[str, Any],
    tmp_path: Path,
) -> None:
    assert built_distribution["status"] == "LOCAL_CANDIDATE_NOT_RELEASE_READY"
    assert built_distribution["package"] == {
        "name": "veriagent-proofflow",
        "version": VERSION,
    }
    assert built_distribution["supply_chain_release_gate"] == "NOT_RUN"
    source = built_distribution["source"]
    assert len(source["base_git_commit"]) in {40, 64}
    assert len(source["base_git_tree"]) in {40, 64}
    assert source["snapshot_stable_during_build"] is True
    assert source["snapshot_sha256"].startswith("sha256:")
    assert source["snapshot_file_count"] > 0
    assert source["exact_commit_binding"] is (source["snapshot_kind"] == "GIT_COMMIT_TREE")
    _artifact(built_distribution, ".whl")
    _artifact(built_distribution, ".tar.gz")

    second_output = tmp_path / "second-dist"
    second = json.loads(
        _run(
            [sys.executable, str(BUILD_SCRIPT), "--output", str(second_output)],
            cwd=tmp_path,
        ).stdout
    )
    assert {record["filename"]: record["sha256"] for record in built_distribution["artifacts"]} == {
        record["filename"]: record["sha256"] for record in second["artifacts"]
    }
    assert (built_distribution["_output"] / "artifact-manifest.json").read_bytes() == (
        second_output / "artifact-manifest.json"
    ).read_bytes()


def test_readme_requires_the_verified_distribution_builder() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    required = (
        "uv run --frozen python scripts/build_installable_distribution.py",
        "artifact-manifest.json",
        "snapshot_kind=GIT_COMMIT_TREE",
        "exact_commit_binding=true",
        "snapshot_kind=WORKTREE_COPY",
        "exact_commit_binding=false",
        "LOCAL_CANDIDATE_NOT_RELEASE_READY",
        "SUPPLY_CHAIN_RELEASE_GATE_REJECTED",
        "直接运行 `uv build`",
    )
    for phrase in required:
        assert phrase in readme


def test_wheel_contains_cli_assets_but_not_repository_browser_demo(
    built_distribution: dict[str, Any],
) -> None:
    wheel = _artifact(built_distribution, ".whl")
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    assert {
        "proofflow/demo_assets/README.md",
        "proofflow/demo_assets/case/contract.json",
        "proofflow/demo_assets/case/manifest.json",
        "proofflow/demo_assets/case/payroll.json",
        "proofflow/demo_assets/case/termination_notice.json",
        "proofflow/demo_assets/rules/cn_labor_contract_law.catalog.json",
    } <= names
    assert "demo/server.py" not in names
    assert not any(name.startswith("public-demo/") for name in names)


def test_sdist_inventory_excludes_repository_only_history_and_test_assets(
    built_distribution: dict[str, Any],
) -> None:
    sdist = _artifact(built_distribution, ".tar.gz")
    with tarfile.open(sdist, mode="r:gz") as archive:
        names = {member.name for member in archive.getmembers()}
    assert sdist.stat().st_size < 250_000
    assert not any(
        forbidden in name
        for name in names
        for forbidden in (
            "/benchmarks/",
            "/demo/",
            "/deploy/",
            "/docs/",
            "/public-demo/",
            "/submission/",
            "/tests/",
            "/third_party/",
        )
    )
    assert not any(name.endswith((".pdf", ".pptx", ".mp4")) for name in names)


def test_clean_commit_build_ignores_live_source_mutation_after_snapshot_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    repository = _create_clean_package_repo(tmp_path)
    monkeypatch.setattr(builder, "ROOT", repository)
    original_run = builder._run
    marker = "LIVE_WORKTREE_TOCTOU_MARKER"
    mutated = False

    def mutate_live_tree_before_uv(
        command: list[str],
        *,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> str:
        nonlocal mutated
        if command[:2] == ["uv", "build"] and not mutated:
            mutated = True
            live_source = repository / "src/proofflow/__init__.py"
            live_source.write_text(
                live_source.read_text(encoding="utf-8") + f"\n# {marker}\n",
                encoding="utf-8",
            )
        return original_run(command, environment=environment, cwd=cwd)

    monkeypatch.setattr(builder, "_run", mutate_live_tree_before_uv)
    manifest = builder.build_distribution(tmp_path / "dist", release=False)

    assert mutated
    assert manifest["source"]["snapshot_kind"] == "GIT_COMMIT_TREE"
    assert manifest["source"]["exact_commit_binding"] is True
    assert manifest["source"]["worktree_clean_observed_before_snapshot"] is True
    assert manifest["source"]["worktree_clean_observed_after_build"] is False
    wheel = next((tmp_path / "dist").glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        installed_init = archive.read("proofflow/__init__.py").decode("utf-8")
    assert marker not in installed_init


def test_private_snapshot_mutate_then_restore_during_uv_build_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    repository = _create_clean_package_repo(tmp_path)
    monkeypatch.setattr(builder, "ROOT", repository)
    original_run = builder._run

    def mutate_private_snapshot_before_uv(
        command: list[str],
        *,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> str:
        if command[:2] == ["uv", "build"]:
            snapshot_source = Path(command[-1]) / "src/proofflow/__init__.py"
            original_payload = snapshot_source.read_bytes()
            snapshot_source.write_bytes(original_payload + b"\n# SNAPSHOT_DRIFT\n")
            try:
                return original_run(command, environment=environment, cwd=cwd)
            finally:
                snapshot_source.write_bytes(original_payload)
        return original_run(command, environment=environment, cwd=cwd)

    monkeypatch.setattr(builder, "_run", mutate_private_snapshot_before_uv)
    with pytest.raises(builder.DistributionBuildError) as rejected:
        builder.build_distribution(tmp_path / "dist", release=False)

    assert rejected.value.code == "BUILD_SOURCE_BINDING_MISMATCH"
    assert list((tmp_path / "dist").iterdir()) == []


def test_builder_rejects_top_level_pth_injected_after_uv_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _load_builder()
    repository = _create_clean_package_repo(tmp_path)
    monkeypatch.setattr(builder, "ROOT", repository)
    original_run = builder._run
    injected = False

    def inject_pth_after_uv(
        command: list[str],
        *,
        environment: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> str:
        nonlocal injected
        result = original_run(command, environment=environment, cwd=cwd)
        if command[:2] == ["uv", "build"]:
            artifact_staging = Path(command[command.index("--out-dir") + 1])
            wheel = next(artifact_staging.glob("*.whl"))
            attacked = _attacked_wheel_payload(wheel, "extra-pth")
            wheel.write_bytes(attacked)
            injected = True
        return result

    monkeypatch.setattr(builder, "_run", inject_pth_after_uv)
    with pytest.raises(builder.DistributionBuildError) as rejected:
        builder.build_distribution(tmp_path / "dist", release=False)

    assert injected
    assert rejected.value.code == "BUILD_SOURCE_BINDING_MISMATCH"
    assert list((tmp_path / "dist").iterdir()) == []


@pytest.mark.parametrize(
    "attack",
    [
        "extra-pth",
        "top-level-package",
        "second-dist-info",
        "path-escape",
        "duplicate-member",
        "record-tamper",
    ],
)
def test_wheel_closed_set_and_record_reject_injected_members(
    built_distribution: dict[str, Any],
    attack: str,
) -> None:
    builder = _load_builder()
    source_records = builder._worktree_inventory(ROOT)
    package = builder._project_metadata(ROOT)
    attacked = _attacked_wheel_payload(_artifact(built_distribution, ".whl"), attack)

    with pytest.raises(builder.DistributionBuildError) as rejected:
        builder._validate_wheel_sources(attacked, source_records, package)

    assert rejected.value.code == "BUILD_SOURCE_BINDING_MISMATCH"


def test_installed_wheel_runs_without_source_checkout(
    built_distribution: dict[str, Any],
    tmp_path: Path,
) -> None:
    _installed_journey(_artifact(built_distribution, ".whl"), tmp_path)


def test_extracted_sdist_without_git_runs_without_source_checkout(
    built_distribution: dict[str, Any],
    tmp_path: Path,
) -> None:
    extracted = _safe_extract_sdist(
        _artifact(built_distribution, ".tar.gz"),
        tmp_path / "extracted",
    )
    _installed_journey(extracted, tmp_path / "journey")


def test_release_mode_is_rejected_while_supply_chain_evidence_is_stale(
    tmp_path: Path,
) -> None:
    completed = _run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--output",
            str(tmp_path / "release"),
            "--release",
        ],
        cwd=tmp_path,
        expected_returncode=2,
    )
    assert json.loads(completed.stderr)["error"]["code"] == ("SUPPLY_CHAIN_RELEASE_GATE_REJECTED")
    assert not (tmp_path / "release").exists()
