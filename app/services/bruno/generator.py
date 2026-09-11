import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List
from app.core.config import settings
from app.schemas.execution_plan import AttackScenario, TargetConfig


class BrunoCollectionGenerator:
    """
    Generates standard Bruno collections and .bru files on disk.
    Organizes test scenarios by category under generated/{project_id}/{run_id}/.
    """

    def __init__(self, base_dir: str | None = None):
        self.base_dir = Path(base_dir or settings.GENERATED_COLLECTIONS_DIR)

    def generate_collection(
        self,
        project_id: str,
        run_id: str,
        scenarios: List[AttackScenario],
        target: TargetConfig
    ) -> Path:
        """
        Creates collection directory, bruno.json, environment file, and .bru files for every scenario.
        Returns the absolute path to the generated collection folder.
        """
        collection_dir = self.base_dir / project_id / run_id
        collection_dir.mkdir(parents=True, exist_ok=True)

        # 1. Write bruno.json
        bruno_meta = {
            "version": "1",
            "name": f"API Guardian Run - {run_id}",
            "type": "collection",
            "ignore": ["node_modules", ".git"]
        }
        with open(collection_dir / "bruno.json", "w", encoding="utf-8") as f:
            json.dump(bruno_meta, f, indent=2)

        # 2. Write environments/local.bru
        env_dir = collection_dir / "environments"
        env_dir.mkdir(exist_ok=True)
        env_content = f"vars {{\n  baseUrl: {target.base_url.rstrip('/')}\n}}\n"
        with open(env_dir / "local.bru", "w", encoding="utf-8") as f:
            f.write(env_content)

        # 3. Write .bru files grouped by category folder
        for idx, scenario in enumerate(scenarios):
            cat_folder_name = self._sanitize_folder_name(scenario.category)
            cat_dir = collection_dir / cat_folder_name
            cat_dir.mkdir(parents=True, exist_ok=True)

            for s_idx, step in enumerate(scenario.steps):
                step_suffix = f"-step-{step.step_number}" if len(scenario.steps) > 1 else ""
                file_name = f"{scenario.attack_id}{step_suffix}.bru"
                file_path = cat_dir / file_name

                bru_content = self._generate_bru_content(
                    scenario=scenario,
                    step=step,
                    seq_num=idx + 1 + s_idx,
                )

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(bru_content)

        return collection_dir.resolve()

    def _sanitize_folder_name(self, category: str) -> str:
        """Converts category string to safe folder name (e.g. 'Role Escalation' -> 'role_escalation')."""
        cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", category.lower()).strip("_")
        return cleaned or "general"

    def _generate_bru_content(
        self,
        scenario: AttackScenario,
        step: Any,
        seq_num: int
    ) -> str:
        """Constructs authentic Bruno file content."""
        method_lower = step.method.lower()
        url_path = step.path.lstrip("/")
        full_url = f"{{{{baseUrl}}}}/{url_path}" if url_path else "{{baseUrl}}"

        # Body definition
        body_type = "none"
        body_content = ""
        if step.body is not None:
            body_type = "json"
            if isinstance(step.body, (dict, list)):
                body_content = f"\nbody:json {{\n  {json.dumps(step.body, indent=2)}\n}}\n"
            else:
                body_content = f"\nbody:json {{\n  {step.body}\n}}\n"

        # Headers block
        headers_lines = []
        for k, v in step.headers.items():
            headers_lines.append(f"  {k}: {v}")
        headers_block = ""
        if headers_lines:
            headers_block = "\nheaders {\n" + "\n".join(headers_lines) + "\n}\n"

        # Query params block
        query_lines = []
        for k, v in step.query_params.items():
            query_lines.append(f"  {k}: {v}")
        query_block = ""
        if query_lines:
            query_block = "\nparams:query {\n" + "\n".join(query_lines) + "\n}\n"

        # Assertions block
        assert_block = f"""
assert {{
  res.status: eq {step.expected_status}
}}
"""

        # Meta block
        meta_block = f"""meta {{
  name: {scenario.attack_id} - {scenario.category} - {step.step_name}
  type: http
  seq: {seq_num}
}}

{method_lower} {{
  url: {full_url}
  body: {body_type}
  auth: none
}}
{headers_block}{query_block}{body_content}{assert_block}"""

        return meta_block.strip() + "\n"
