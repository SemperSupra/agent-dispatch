"""
WinBot OpenAPI Conformance Tests
Validates the generated OpenAPI 3.1 schema against the standard specification.

Mirrors WineBot's test_conformance_openapi.py pattern.
Requires: openapi-spec-validator
"""

import pytest
from openapi_spec_validator import validate


class TestOpenAPIConformance:
    """Validate the /openapi.json schema against the OpenAPI 3.1 standard."""

    def test_openapi_document_is_valid_31(self, client):
        """The generated OpenAPI document must pass spec validation."""
        response = client.get("/openapi.json")
        assert response.status_code == 200, f"OpenAPI endpoint returned {response.status_code}"
        spec = response.json()

        # Must claim OpenAPI 3.1.x
        assert spec["openapi"].startswith("3."), (
            f"Expected OpenAPI 3.x, got {spec['openapi']}"
        )

        try:
            validate(spec)
        except Exception as e:
            pytest.fail(f"OpenAPI 3.1 validation failed: {e}")

    def test_openapi_has_operation_ids(self, client):
        """Every operation must have a unique operationId for tool/AI discoverability."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        spec = response.json()

        seen_ids = set()
        for path, path_item in spec["paths"].items():
            for method in ("get", "post", "put", "patch", "delete", "options"):
                operation = path_item.get(method)
                if not operation:
                    continue
                op_id = operation.get("operationId")
                assert op_id, (
                    f"Missing operationId in {method.upper()} {path}"
                )
                assert op_id not in seen_ids, (
                    f"Duplicate operationId '{op_id}' in {method.upper()} {path}"
                )
                seen_ids.add(op_id)

    def test_paths_use_kebab_case(self, client):
        """All paths should use kebab-case for consistency."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        spec = response.json()

        for path in spec["paths"]:
            if "{" in path:
                continue  # skip parameterized paths like /health/{target}
            segments = [s for s in path.split("/") if s and not s.startswith("{")]
            for seg in segments:
                assert not any(c.isupper() for c in seg), (
                    f"Path segment '{seg}' in '{path}' should be lowercase"
                )

    def test_validation_errors_are_documented(self, client):
        """FastAPI auto-generates 422 (validation error) responses for POST endpoints with Pydantic models."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        spec = response.json()

        has_422 = False
        for path_item in spec["paths"].values():
            for method, operation in path_item.items():
                if method not in ("get", "post", "put", "patch", "delete"):
                    continue
                for status in operation.get("responses", {}):
                    if status == "422":
                        has_422 = True
                        break

        assert has_422, "No endpoint documents a 422 (validation error) response"

    def test_security_scheme_is_documented(self, client):
        """The API token auth scheme should appear in the OpenAPI components/securitySchemes."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        spec = response.json()

        components = spec.get("components", {})
        schemes = components.get("securitySchemes", {})
        assert schemes, (
            "No securitySchemes documented. API requires X-API-Key, "
            "this must be reflected in the OpenAPI schema."
        )

        # At least one scheme should reference an API key header
        found_api_key = False
        for scheme_name, scheme_def in schemes.items():
            if scheme_def.get("type") == "apiKey":
                if scheme_def.get("in") == "header":
                    found_api_key = True
                    break

        assert found_api_key, (
            f"Found schemes {list(schemes.keys())} but none are apiKey in header. "
            "X-API-Key auth must be documented."
        )
