import json
import re
import textwrap
from typing import Any, Dict, List, Optional, Tuple, Set
import yaml

from app.core.exceptions import SpecParsingError
from app.core.logging import logger

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class OpenAPIParser:
    """
    Parses OpenAPI 3.x and Swagger 2.0 specifications from YAML or JSON.
    Performs internal $ref resolution and normalizes endpoints, parameters, schemas, and security.
    """

    def __init__(self, raw_spec: str | Dict[str, Any]):
        self.raw_content: str = ""
        self.spec: Dict[str, Any] = {}
        self.spec_format: str = "json"

        if isinstance(raw_spec, dict):
            self.spec = raw_spec
            self.raw_content = json.dumps(raw_spec, indent=2)
            self.spec_format = "json"
        elif isinstance(raw_spec, str):
            self.raw_content = raw_spec
            self.spec, self.spec_format = self._parse_string_spec(raw_spec)
        else:
            raise SpecParsingError(f"Unsupported spec input type: {type(raw_spec)}")

        self.openapi_version = self._detect_version()
        self._resolve_all_refs()

    def _parse_string_spec(self, text: str) -> Tuple[Dict[str, Any], str]:
        """Attempts JSON parsing first, then YAML with dedent handling."""
        cleaned = textwrap.dedent(text).strip()
        if not cleaned:
            raise SpecParsingError("OpenAPI specification is empty.")

        # Try JSON
        if cleaned.startswith("{") or cleaned.startswith("["):
            try:
                parsed = json.loads(cleaned)
                if isinstance(parsed, dict):
                    return parsed, "json"
            except json.JSONDecodeError:
                pass

        # Try YAML
        try:
            parsed = yaml.safe_load(cleaned)
            if isinstance(parsed, dict):
                return parsed, "yaml"
            raise SpecParsingError("Parsed YAML specification is not an object/dictionary.")
        except Exception as e:
            raise SpecParsingError(f"Failed to parse specification as JSON or YAML: {str(e)}")

    def _detect_version(self) -> str:
        """Identifies OpenAPI 3.x vs Swagger 2.0."""
        if "openapi" in self.spec:
            return str(self.spec["openapi"])
        elif "swagger" in self.spec:
            return str(self.spec["swagger"])
        else:
            raise SpecParsingError("Specification missing 'openapi' or 'swagger' root version field.")

    def _resolve_all_refs(self) -> None:
        """Resolves local '#/...' references across the entire dictionary."""
        def resolve_ref(ref_path: str, root: Dict[str, Any]) -> Any:
            if not ref_path.startswith("#/"):
                return {"$ref_external": ref_path}
            parts = ref_path[2:].split("/")
            current = root
            for part in parts:
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return current

        def deep_resolve(node: Any, root: Dict[str, Any], visited: Set[int]) -> Any:
            node_id = id(node)
            if node_id in visited:
                return node
            visited.add(node_id)

            if isinstance(node, dict):
                if "$ref" in node and isinstance(node["$ref"], str):
                    resolved = resolve_ref(node["$ref"], root)
                    if resolved and isinstance(resolved, dict):
                        merged = {k: v for k, v in node.items() if k != "$ref"}
                        resolved_copy = deep_resolve(dict(resolved), root, visited)
                        if isinstance(resolved_copy, dict):
                            resolved_copy.update(merged)
                            return resolved_copy
                        return resolved_copy
                return {k: deep_resolve(v, root, visited) for k, v in node.items()}
            elif isinstance(node, list):
                return [deep_resolve(item, root, visited) for item in node]
            return node

        self.spec = deep_resolve(self.spec, self.spec, set())

    def get_metadata(self) -> Dict[str, Any]:
        """Extracts title, version, description, and base URL."""
        info = self.spec.get("info", {})
        title = info.get("title", "Untitled API")
        version = info.get("version", "1.0.0")
        description = info.get("description", "")

        target_base_url = None
        servers = self.spec.get("servers", [])
        if servers and isinstance(servers, list) and len(servers) > 0:
            target_base_url = servers[0].get("url")
        elif "host" in self.spec:
            schemes = self.spec.get("schemes", ["http"])
            scheme = schemes[0] if schemes else "http"
            base_path = self.spec.get("basePath", "")
            target_base_url = f"{scheme}://{self.spec['host']}{base_path}"

        return {
            "title": title,
            "version": str(version),
            "openapi_version": self.openapi_version,
            "description": description,
            "target_base_url": target_base_url,
            "raw_content": self.raw_content,
            "spec_format": self.spec_format,
        }

    def get_security_schemes(self) -> List[Dict[str, Any]]:
        """Extracts security scheme definitions (OpenAPI 3.x or Swagger 2.0)."""
        schemes: List[Dict[str, Any]] = []

        raw_schemes = self.spec.get("components", {}).get("securitySchemes", {})
        if not raw_schemes:
            raw_schemes = self.spec.get("securityDefinitions", {})

        if isinstance(raw_schemes, dict):
            for name, defn in raw_schemes.items():
                if not isinstance(defn, dict):
                    continue
                scheme_type = defn.get("type", "none").lower()
                scheme_format = defn.get("scheme", "").lower()
                bearer_format = defn.get("bearerFormat", "")

                normalized_type = scheme_type
                if scheme_type == "http":
                    if scheme_format == "bearer":
                        normalized_type = "bearer"
                    elif scheme_format == "basic":
                        normalized_type = "basic"
                    else:
                        normalized_type = scheme_format or "bearer"
                elif scheme_type == "apikey":
                    normalized_type = "apikey"
                elif scheme_type == "oauth2":
                    normalized_type = "oauth2"
                elif scheme_type == "basic":
                    normalized_type = "basic"

                token_location = defn.get("in", "")
                header_name = defn.get("name", "")
                if normalized_type == "bearer":
                    token_location = "header"
                    header_name = header_name or "Authorization"
                elif normalized_type == "basic":
                    token_location = "header"
                    header_name = header_name or "Authorization"

                scopes = {}
                if "flows" in defn:
                    for flow_data in defn["flows"].values():
                        if isinstance(flow_data, dict) and "scopes" in flow_data:
                            scopes.update(flow_data["scopes"])
                elif "scopes" in defn:
                    scopes = defn["scopes"]

                schemes.append({
                    "scheme_name": name,
                    "scheme_type": normalized_type,
                    "security_required": True,
                    "token_location": token_location,
                    "header_name": header_name,
                    "bearer_format": bearer_format,
                    "scopes": scopes if scopes else None,
                    "description": defn.get("description"),
                })

        return schemes

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Parses all paths and operations into normalized endpoints."""
        endpoints: List[Dict[str, Any]] = []
        paths = self.spec.get("paths", {})
        global_security = self.spec.get("security", [])

        if not isinstance(paths, dict):
            return endpoints

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_level_params = path_item.get("parameters", [])

            for method_str, op_item in path_item.items():
                method_lower = method_str.lower()
                if method_lower not in HTTP_METHODS or not isinstance(op_item, dict):
                    continue

                operation_id = op_item.get("operationId")
                summary = op_item.get("summary")
                description = op_item.get("description")
                tags = op_item.get("tags", [])

                op_security = op_item.get("security", None)
                if op_security is not None:
                    security_schemes = op_security
                    security_required = len(op_security) > 0
                else:
                    security_schemes = global_security
                    security_required = len(global_security) > 0

                op_params = op_item.get("parameters", [])
                all_params_raw = list(path_level_params) + list(op_params)
                parameters = self._normalize_parameters(all_params_raw, path_str)
                schemas = self._extract_schemas(op_item)

                responses = op_item.get("responses", {})
                responses_summary = [str(k) for k in responses.keys()] if isinstance(responses, dict) else []

                endpoints.append({
                    "method": method_lower.upper(),
                    "path": path_str,
                    "operation_id": operation_id,
                    "summary": summary,
                    "description": description,
                    "security_required": security_required,
                    "tags": tags if isinstance(tags, list) else [],
                    "security_schemes": security_schemes,
                    "responses_summary": responses_summary,
                    "parameters": parameters,
                    "schemas": schemas,
                })

        return endpoints

    def _normalize_parameters(self, raw_params: List[Any], path_str: str) -> List[Dict[str, Any]]:
        """Extracts and normalizes parameters, inferring path params if missing."""
        params: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str]] = set()

        for param in raw_params:
            if not isinstance(param, dict):
                continue
            name = param.get("name")
            location = param.get("in", "query")
            if not name:
                continue

            key = (str(name), str(location))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            param_schema = param.get("schema", {})
            param_type = "string"
            enum_values = None
            if isinstance(param_schema, dict):
                param_type = param_schema.get("type", "string")
                enum_values = param_schema.get("enum")
            elif "type" in param:
                param_type = param.get("type", "string")
                enum_values = param.get("enum")

            required = bool(param.get("required", location == "path"))
            default_val = str(param.get("default")) if param.get("default") is not None else None

            params.append({
                "name": str(name),
                "location": str(location),
                "param_type": str(param_type),
                "required": required,
                "default_value": default_val,
                "enum_values": enum_values,
                "schema_def": param_schema if isinstance(param_schema, dict) else None,
                "description": param.get("description"),
            })

        path_variables = re.findall(r"\{([a-zA-Z0-9_]+)\}", path_str)
        for var in path_variables:
            key = (var, "path")
            if key not in seen_keys:
                seen_keys.add(key)
                params.append({
                    "name": var,
                    "location": "path",
                    "param_type": "string",
                    "required": True,
                    "default_value": None,
                    "enum_values": None,
                    "schema_def": {"type": "string"},
                    "description": f"Path variable {var}",
                })

        return params

    def _extract_schemas(self, op_item: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts requestBody and response schemas."""
        schemas: List[Dict[str, Any]] = []

        request_body = op_item.get("requestBody", {})
        if isinstance(request_body, dict) and "content" in request_body:
            content = request_body.get("content", {})
            for ctype, cdata in content.items():
                if isinstance(cdata, dict) and "schema" in cdata:
                    schemas.append({
                        "schema_type": "request_body",
                        "status_code": None,
                        "content_type": ctype,
                        "schema_json": cdata["schema"],
                        "description": request_body.get("description"),
                    })

        for param in op_item.get("parameters", []):
            if isinstance(param, dict) and param.get("in") == "body" and "schema" in param:
                schemas.append({
                    "schema_type": "request_body",
                    "status_code": None,
                    "content_type": "application/json",
                    "schema_json": param["schema"],
                    "description": param.get("description"),
                })

        responses = op_item.get("responses", {})
        if isinstance(responses, dict):
            for status_code, resp_data in responses.items():
                if not isinstance(resp_data, dict):
                    continue

                if "content" in resp_data and isinstance(resp_data["content"], dict):
                    for ctype, cdata in resp_data["content"].items():
                        if isinstance(cdata, dict) and "schema" in cdata:
                            schemas.append({
                                "schema_type": "response_body",
                                "status_code": str(status_code),
                                "content_type": ctype,
                                "schema_json": cdata["schema"],
                                "description": resp_data.get("description"),
                            })
                elif "schema" in resp_data:
                    schemas.append({
                        "schema_type": "response_body",
                        "status_code": str(status_code),
                        "content_type": "application/json",
                        "schema_json": resp_data["schema"],
                        "description": resp_data.get("description"),
                    })

        return schemas
