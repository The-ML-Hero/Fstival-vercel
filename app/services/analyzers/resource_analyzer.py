import re
from typing import Any, Dict, List, Set, Tuple
from app.schemas.resource import ResourceAnalysisResult, ResourceEntityResponse, ResourceRelationship


class ResourceAnalyzer:
    """
    Identifies core business resources and models entity relationships (e.g. User -> Order -> Payment).
    Constructs CRUD operation maps for BOLA/IDOR and workflow attack generation.
    """

    def analyze(self, endpoints_raw: List[Dict[str, Any]]) -> ResourceAnalysisResult:
        resources_dict: Dict[str, Dict[str, Any]] = {}

        def get_or_create_resource(res_name: str) -> Dict[str, Any]:
            norm_name = res_name.capitalize().rstrip("s")
            if not norm_name or len(norm_name) < 2:
                norm_name = res_name.capitalize()

            if norm_name not in resources_dict:
                resources_dict[norm_name] = {
                    "name": norm_name,
                    "description": f"Domain resource '{norm_name}'",
                    "endpoints": set(),
                    "crud_operations": {},
                    "relationships": [],
                }
            return resources_dict[norm_name]

        # 1. Parse REST path patterns: /resource, /resource/{id}, /parent/{parentId}/child/{childId}
        for ep in endpoints_raw:
            path = ep.get("path", "")
            method = ep.get("method", "GET").upper()

            # Split path segments
            segments = [s for s in path.strip("/").split("/") if s]
            if not segments:
                continue

            # Identify resources from static segments preceding parameter segments
            resource_trail: List[str] = []
            for i, seg in enumerate(segments):
                if seg.startswith("{") and seg.endswith("}"):
                    continue
                # Skip common utility prefixes like 'api', 'v1', 'v2', 'v3', 'admin', 'auth'
                if seg.lower() in {"api", "v1", "v2", "v3", "auth", "oauth"}:
                    continue
                resource_trail.append(seg)

            if not resource_trail:
                continue

            primary_segment = resource_trail[-1]
            resource_obj = get_or_create_resource(primary_segment)
            resource_obj["endpoints"].add(f"{method} {path}")

            # Assign CRUD operations
            is_collection = not (segments[-1].startswith("{") and segments[-1].endswith("}"))
            if method == "POST" and is_collection:
                resource_obj["crud_operations"]["create"] = f"{method} {path}"
            elif method == "GET" and not is_collection:
                resource_obj["crud_operations"]["read"] = f"{method} {path}"
            elif method == "GET" and is_collection:
                resource_obj["crud_operations"]["list"] = f"{method} {path}"
            elif method in {"PUT", "PATCH"} and not is_collection:
                resource_obj["crud_operations"]["update"] = f"{method} {path}"
            elif method == "DELETE" and not is_collection:
                resource_obj["crud_operations"]["delete"] = f"{method} {path}"

            # Detect hierarchical relationships from multi-level paths (e.g. /users/{id}/orders)
            if len(resource_trail) >= 2:
                parent_seg = resource_trail[-2]
                parent_res = get_or_create_resource(parent_seg)
                child_res_name = resource_obj["name"]

                rel = ResourceRelationship(
                    target_resource=child_res_name,
                    relationship_type="has_many" if is_collection else "belongs_to",
                    evidence_endpoint=f"{method} {path}",
                    foreign_key_parameter=f"{parent_seg.rstrip('s').lower()}_id"
                )
                if not any(r.target_resource == rel.target_resource and r.relationship_type == rel.relationship_type for r in parent_res["relationships"]):
                    parent_res["relationships"].append(rel)

        # 2. Cross-reference parameters to infer foreign key relationships (e.g. order_id in /payments)
        for ep in endpoints_raw:
            path = ep.get("path", "")
            method = ep.get("method", "GET").upper()
            params = ep.get("parameters", [])

            for param in params:
                pname = param.get("name", "").lower()
                # If parameter ends with '_id' or 'id' e.g. 'patient_id', 'order_id', 'user_id'
                if pname.endswith("_id") or (pname.endswith("id") and len(pname) > 2):
                    extracted_entity = pname[:-3] if pname.endswith("_id") else pname[:-2]
                    entity_name = extracted_entity.capitalize()

                    for rname, rdata in resources_dict.items():
                        if rname.lower() == entity_name.lower():
                            # Find which resource owns this endpoint
                            for other_rname, other_rdata in resources_dict.items():
                                if other_rname != rname and any(f"{method} {path}" in ep_str for ep_str in other_rdata["endpoints"]):
                                    rel = ResourceRelationship(
                                        target_resource=rname,
                                        relationship_type="references",
                                        evidence_endpoint=f"{method} {path}",
                                        foreign_key_parameter=pname
                                    )
                                    if not any(r.target_resource == rel.target_resource and r.relationship_type == rel.relationship_type for r in other_rdata["relationships"]):
                                        other_rdata["relationships"].append(rel)

        output_resources: List[ResourceEntityResponse] = []
        for r_name, r_data in resources_dict.items():
            output_resources.append(ResourceEntityResponse(
                name=r_name,
                description=r_data["description"],
                endpoints=sorted(list(r_data["endpoints"])),
                crud_operations=r_data["crud_operations"],
                relationships=r_data["relationships"],
            ))

        output_resources.sort(key=lambda x: len(x.endpoints), reverse=True)

        return ResourceAnalysisResult(
            resources=output_resources,
            identified_resource_count=len(output_resources),
        )
