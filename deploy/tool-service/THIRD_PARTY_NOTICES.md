# ProofFlow tool-service third-party notices

This file covers only the Python distributions currently pinned in
`deploy/tool-service/requirements.lock`. The names, versions, SPDX license expressions,
license-file declarations, and source links below were verified from the installed Core
Metadata for those exact locked versions. The original dependency set was checked on
2026-08-20; the three ActionCertificate additions were checked on 2026-08-29.

| Distribution | Version | License expression | Declared license file | Source |
|---|---:|---|---|---|
| `annotated-types` | `0.8.0` | `MIT` | `LICENSE` | https://github.com/annotated-types/annotated-types |
| `cffi` | `2.1.1` | `MIT-0` | `LICENSE` | https://github.com/python-cffi/cffi |
| `cryptography` | `46.0.7` | `Apache-2.0 OR BSD-3-Clause` | `LICENSE`, `LICENSE.APACHE`, `LICENSE.BSD` | https://github.com/pyca/cryptography |
| `pycparser` | `3.0` | `BSD-3-Clause` | `LICENSE` | https://github.com/eliben/pycparser |
| `pydantic` | `2.13.4` | `MIT` | `LICENSE` | https://github.com/pydantic/pydantic |
| `pydantic-core` | `2.46.4` | `MIT` | `LICENSE` | https://github.com/pydantic/pydantic/tree/main/pydantic-core |
| `typing-extensions` | `4.16.0` | `PSF-2.0` | `LICENSE` | https://github.com/python/typing_extensions |
| `typing-inspection` | `0.4.4` | `MIT` | `LICENSE` | https://github.com/pydantic/typing-inspection |

When a new image is built from this lock, each distribution's declared license files are installed
under its `.dist-info/licenses/` path. ProofFlow's own Apache License 2.0 text and `NOTICE` are
copied to `/usr/share/doc/proofflow/` alongside this file. The published historical image and SBOM
predate the ActionCertificate dependency additions, so this updated inventory is not evidence that
those packages exist in that old image; the historical evidence is explicitly stale.

This inventory does not identify or license the CPython base image or its operating-system
packages. An image-level SBOM and vulnerability scan are separate release gates; neither
their existence nor a clean result is implied by this notice.
