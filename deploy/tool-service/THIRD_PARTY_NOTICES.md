# ProofFlow tool-service third-party notices

This file covers only the Python distributions pinned in
`deploy/tool-service/requirements.lock`. The names, versions, SPDX license expressions,
license-file declarations, and source links below were verified from the installed Core
Metadata for those exact locked versions on 2026-08-20.

| Distribution | Version | License expression | Declared license file | Source |
|---|---:|---|---|---|
| `annotated-types` | `0.8.0` | `MIT` | `LICENSE` | https://github.com/annotated-types/annotated-types |
| `pydantic` | `2.13.4` | `MIT` | `LICENSE` | https://github.com/pydantic/pydantic |
| `pydantic-core` | `2.46.4` | `MIT` | `LICENSE` | https://github.com/pydantic/pydantic/tree/main/pydantic-core |
| `typing-extensions` | `4.16.0` | `PSF-2.0` | `LICENSE` | https://github.com/python/typing_extensions |
| `typing-inspection` | `0.4.4` | `MIT` | `LICENSE` | https://github.com/pydantic/typing-inspection |

The complete declared license text for each distribution remains installed in that
distribution's `.dist-info/licenses/LICENSE` path inside the image. ProofFlow's own Apache
License 2.0 text and `NOTICE` are installed under `/usr/share/doc/proofflow/` alongside this
file.

This inventory does not identify or license the CPython base image or its operating-system
packages. An image-level SBOM and vulnerability scan are separate release gates; neither
their existence nor a clean result is implied by this notice.
