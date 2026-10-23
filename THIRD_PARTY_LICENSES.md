# Third-party licenses

This project uses the Python packages below. Their licenses apply to those
packages; the project's own code is licensed under the MIT License in `LICENSE`.

## Runtime dependencies

| Package | Pinned version | License | License/source |
| --- | --- | --- | --- |
| FastAPI | 0.115.12 | MIT | [LICENSE](https://github.com/fastapi/fastapi/blob/master/LICENSE) |
| Uvicorn (`standard` extra) | 0.34.0 | BSD-3-Clause | [LICENSE](https://github.com/encode/uvicorn/blob/master/LICENSE.md) |
| HTTPX (`http2` extra) | 0.28.1 | BSD-3-Clause | [LICENSE](https://github.com/encode/httpx/blob/master/LICENSE.md) |
| PyJWT (`crypto` extra) | 2.10.1 | MIT | [LICENSE](https://github.com/jpadilla/pyjwt/blob/master/LICENSE) |
| pydantic-settings | 2.8.1 | MIT | [Project metadata](https://github.com/pydantic/pydantic-settings/blob/main/pyproject.toml) |
| cbor2 | 5.6.5 | MIT | [PyPI release metadata](https://pypi.org/project/cbor2/5.6.5/) |

## Development dependency

| Package | Pinned version | License | License/source |
| --- | --- | --- | --- |
| pytest | 8.3.5 | MIT | [LICENSE](https://github.com/pytest-dev/pytest/blob/main/LICENSE) |

The extras above install additional transitive packages. This repository does
not vendor their source code; each package retains its own license and notices.
The Home Assistant base image and its operating-system packages also carry
their respective licenses. Review the package and image metadata for the exact
resolved versions when producing a redistributable binary image or software
bill of materials.

The App Attestation root certificate is obtained from Apple's official
[Private PKI repository](https://www.apple.com/certificateauthority/private/)
and is used as a trust anchor for certificate validation, following Apple's
[App Attest validation guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide).
