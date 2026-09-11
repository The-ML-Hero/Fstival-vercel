import re
from typing import Any, Dict, List, Set
from app.schemas.role import InferredRoleResponse, RoleAnalysisResult

KNOWN_ROLE_KEYWORDS = {
    "admin": ["admin", "administrator", "superadmin", "root"],
    "manager": ["manager", "supervisor", "lead"],
    "doctor": ["doctor", "physician", "clinician", "practitioner"],
    "nurse": ["nurse", "medical_assistant"],
    "patient": ["patient", "client", "customer"],
    "user": ["user", "member", "customer", "authenticated"],
    "moderator": ["moderator", "reviewer"],
    "billing": ["billing", "finance", "accountant"],
    "system": ["system", "service", "internal"],
    "guest": ["guest", "public", "anonymous"],
}


class RoleAnalyzer:
    """
    Infers roles and permissions from paths, scopes, tags, and request schemas.
    Treats inferences as hypotheses with associated confidence, reasoning, and evidence.
    """

    def analyze(
        self,
        endpoints_raw: List[Dict[str, Any]],
        security_schemes_raw: List[Dict[str, Any]]
    ) -> RoleAnalysisResult:
        roles_map: Dict[str, Dict[str, Any]] = {}

        def ensure_role(rname: str) -> Dict[str, Any]:
            rname = rname.lower().strip()
            if rname not in roles_map:
                roles_map[rname] = {
                    "role_name": rname,
                    "confidence": 0.5,
                    "reasoning_points": [],
                    "evidence": [],
                    "associated_endpoints": set(),
                }
            return roles_map[rname]

        # 1. Inspect OAuth2 scopes for roles
        for scheme in security_schemes_raw:
            scopes = scheme.get("scopes") or {}
            for scope_name, scope_desc in scopes.items():
                scope_lower = scope_name.lower()
                for canonical_role, aliases in KNOWN_ROLE_KEYWORDS.items():
                    if any(alias in scope_lower for alias in aliases):
                        r = ensure_role(canonical_role)
                        r["confidence"] = max(r["confidence"], 0.90)
                        r["evidence"].append(f"OAuth2 scope: '{scope_name}' ({scope_desc})")
                        r["reasoning_points"].append(f"Security scope explicitly mandates '{scope_name}' permission.")

        # 2. Inspect endpoints (paths, tags, parameters, schemas)
        for ep in endpoints_raw:
            path = ep.get("path", "")
            method = ep.get("method", "GET")
            tags = ep.get("tags", [])
            summary = (ep.get("summary") or "").lower()
            desc = (ep.get("description") or "").lower()
            endpoint_identifier = f"{method} {path}"

            # Check path segments
            path_segments = [seg.lower() for seg in path.strip("/").split("/")]

            for canonical_role, aliases in KNOWN_ROLE_KEYWORDS.items():
                matched_aliases = [alias for alias in aliases if alias in path_segments]
                if matched_aliases:
                    r = ensure_role(canonical_role)
                    r["associated_endpoints"].add(endpoint_identifier)
                    confidence = 0.88 if canonical_role == "admin" else 0.75
                    r["confidence"] = max(r["confidence"], confidence)
                    r["evidence"].append(f"Path segment: '{path}' contains '{matched_aliases[0]}'")
                    r["reasoning_points"].append(f"Endpoint path '{path}' indicates restricted access for {canonical_role}.")

                # Check tags
                for tag in tags:
                    tag_lower = tag.lower()
                    if any(alias in tag_lower for alias in aliases):
                        r = ensure_role(canonical_role)
                        r["associated_endpoints"].add(endpoint_identifier)
                        r["confidence"] = max(r["confidence"], 0.70)
                        r["evidence"].append(f"Tag '{tag}' on {endpoint_identifier}")
                        r["reasoning_points"].append(f"Tag categorization '{tag}' matches {canonical_role} role.")

            # Check request/response schemas for role-related fields (e.g., 'role', 'roles', 'is_admin')
            for schema in ep.get("schemas", []):
                schema_json = schema.get("schema_json", {})
                props = schema_json.get("properties", {})
                for prop_name, prop_def in props.items():
                    prop_lower = prop_name.lower()
                    if prop_lower in {"role", "roles", "user_role", "is_admin", "user_type"}:
                        enum_vals = prop_def.get("enum")
                        if enum_vals and isinstance(enum_vals, list):
                            for ev in enum_vals:
                                ev_str = str(ev).lower()
                                r = ensure_role(ev_str)
                                r["confidence"] = max(r["confidence"], 0.95)
                                r["evidence"].append(f"Schema property '{prop_name}' enum value '{ev}' on {endpoint_identifier}")
                                r["reasoning_points"].append(f"Schema explicitly enumerates role value '{ev}'.")
                                r["associated_endpoints"].add(endpoint_identifier)

        # Default fallback roles if none detected
        if not roles_map:
            roles_map["user"] = {
                "role_name": "user",
                "confidence": 0.60,
                "reasoning_points": ["Standard authenticated user role assumed for protected endpoints."],
                "evidence": ["General API endpoints"],
                "associated_endpoints": {f"{ep['method']} {ep['path']}" for ep in endpoints_raw if ep.get("security_required")},
            }
            roles_map["admin"] = {
                "role_name": "admin",
                "confidence": 0.50,
                "reasoning_points": ["Administrative role assumed for privileged management."],
                "evidence": ["System operations"],
                "associated_endpoints": set(),
            }

        detected_roles: List[InferredRoleResponse] = []
        for r_name, r_data in roles_map.items():
            reasoning_summary = " ".join(dict.fromkeys(r_data["reasoning_points"])) or f"Role {r_name} inferred from API context."
            unique_evidence = list(dict.fromkeys(r_data["evidence"]))[:10]
            detected_roles.append(InferredRoleResponse(
                role_name=r_name,
                confidence=round(r_data["confidence"], 2),
                reasoning=reasoning_summary,
                evidence=unique_evidence,
                associated_endpoints=sorted(list(r_data["associated_endpoints"])),
            ))

        detected_roles.sort(key=lambda x: x.confidence, reverse=True)

        return RoleAnalysisResult(
            detected_roles=detected_roles,
            hierarchical_levels=[r.role_name for r in detected_roles],
        )
