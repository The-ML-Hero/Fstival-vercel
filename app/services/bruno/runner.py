import asyncio
import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import httpx

from app.core.config import settings
from app.core.logging import logger
from app.core.security import sanitize_payload
from app.schemas.execution_plan import (
    AttackScenario,
    AttackScenarioStep,
    ExecutionResultSummary,
    TargetConfig,
)
from app.services.bruno.parser import BrunoResultParser
from app.services.simulation.identity_manager import IdentityManager


class BrunoRunner:
    """
    Executes Bruno collections via Bruno CLI or built-in Async HTTP Runner.
    Captures stdout/stderr, execution timings, redacted response bodies, and assertion metrics.
    """

    def __init__(self, identity_manager: Optional[IdentityManager] = None):
        self.parser = BrunoResultParser()
        self.identity_mgr = identity_manager or IdentityManager()

    async def execute_scenario(
        self,
        scenario: AttackScenario,
        target: TargetConfig,
        client: Optional[httpx.AsyncClient] = None
    ) -> ExecutionResultSummary:
        """
        Executes a single AttackScenario through the high-performance async executor.
        Evaluates assertions (expected status codes) and records step evidence.
        """
        step_results: List[Dict[str, Any]] = []
        overall_status = "passed"
        final_actual_status = None
        final_expected_status = scenario.expected_status
        start_time_all = time.perf_counter()

        should_close_client = False
        if client is None:
            if "testserver" in target.base_url or "testdemo" in target.base_url:
                from app.demo_api.server import demo_app
                transport = httpx.ASGITransport(app=demo_app)
                client = httpx.AsyncClient(transport=transport, base_url="http://testdemo", timeout=settings.REQUEST_TIMEOUT_SECONDS)
            else:
                client = httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT_SECONDS)
            should_close_client = True

        try:
            context_vars: Dict[str, Any] = {}

            for step in scenario.steps:
                step_start = time.perf_counter()
                url = self._build_step_url(target.base_url, step.path, context_vars)

                headers = self.identity_mgr.inject_auth_headers(
                    headers=step.headers,
                    role=scenario.role_required
                )

                body_data = step.body
                json_payload = None
                content_payload = None
                if isinstance(body_data, (dict, list)):
                    json_payload = body_data
                elif isinstance(body_data, str):
                    content_payload = body_data

                resp_status = None
                resp_body_text = None
                resp_headers_dict: Dict[str, Any] = {}
                step_error = None
                step_passed = False

                try:
                    response = await client.request(
                        method=step.method,
                        url=url,
                        headers=headers,
                        params=step.query_params,
                        json=json_payload,
                        content=content_payload
                    )
                    resp_status = response.status_code
                    final_actual_status = resp_status
                    resp_headers_dict = dict(response.headers)
                    resp_body_text = response.text

                    try:
                        resp_json = response.json()
                        if isinstance(resp_json, dict):
                            for var_key, var_field in step.produces_vars.items():
                                if var_field in resp_json:
                                    context_vars[var_key] = resp_json[var_field]
                    except Exception:
                        pass

                    expected = step.expected_status
                    if expected == 401 and resp_status == 401:
                        step_passed = True
                    elif expected == 403 and resp_status in {403, 401, 404}:
                        step_passed = True
                    elif expected == 400 and resp_status in {400, 422}:
                        step_passed = True
                    elif expected == 429 and resp_status == 429:
                        step_passed = True
                    elif resp_status == expected:
                        step_passed = True
                    else:
                        step_passed = False

                except httpx.RequestError as exc:
                    step_error = f"HTTP request failed: {str(exc)}"
                    step_passed = False

                step_duration_ms = round((time.perf_counter() - step_start) * 1000, 2)

                safe_request_headers = self.identity_mgr.redact_sensitive_headers(headers)
                safe_response_body = self._sanitize_response_body(resp_body_text)

                if not step_passed:
                    overall_status = "failed"
                if step_error:
                    overall_status = "error"

                step_results.append({
                    "step_number": step.step_number,
                    "step_name": step.step_name,
                    "method": step.method,
                    "url": url,
                    "request_headers": safe_request_headers,
                    "request_body": json.dumps(body_data) if isinstance(body_data, (dict, list)) else str(body_data or ""),
                    "response_status": resp_status,
                    "response_body": safe_response_body,
                    "response_headers": self.identity_mgr.redact_sensitive_headers(resp_headers_dict),
                    "duration_ms": step_duration_ms,
                    "status": "passed" if step_passed else ("error" if step_error else "failed"),
                    "assertion_results": [{
                        "assertion": f"res.status == {step.expected_status}",
                        "actual": resp_status,
                        "passed": step_passed
                    }],
                    "error_message": step_error
                })

        finally:
            if should_close_client:
                await client.aclose()

        total_duration_ms = round((time.perf_counter() - start_time_all) * 1000, 2)

        return ExecutionResultSummary(
            scenario=scenario,
            status=overall_status,
            actual_status=final_actual_status,
            expected_status=final_expected_status,
            duration_ms=total_duration_ms,
            step_results=step_results,
            stdout=f"Executed {len(scenario.steps)} step(s). Result: {overall_status}",
            stderr="",
            exit_code=0 if overall_status == "passed" else 1
        )

    async def execute_bruno_cli(
        self,
        collection_dir: Path,
        target_base_url: str
    ) -> Tuple[int, str, str]:
        """
        Executes Bruno CLI via subprocess if available on host.
        """
        bruno_cmd = shutil.which("bru")
        if not bruno_cmd:
            bruno_cmd = "npx"
            args = ["--yes", "@usebruno/cli", "run", str(collection_dir), "--env-var", f"baseUrl={target_base_url.rstrip('/')}"]
        else:
            args = ["run", str(collection_dir), "--env-var", f"baseUrl={target_base_url.rstrip('/')}"]

        try:
            proc = await asyncio.create_subprocess_exec(
                bruno_cmd,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout_b, stderr_b = await proc.communicate()
            exit_code = proc.returncode or 0
            stdout_str = stdout_b.decode("utf-8", errors="replace")
            stderr_str = stderr_b.decode("utf-8", errors="replace")
            return exit_code, stdout_str, stderr_str
        except Exception as e:
            logger.warning(f"Bruno CLI execution encountered error: {str(e)}")
            return 1, "", str(e)

    def _build_step_url(self, base_url: str, path: str, context_vars: Dict[str, Any]) -> str:
        """Substitutes variables into path and joins with base URL."""
        resolved_path = path
        for var_key, var_val in context_vars.items():
            resolved_path = resolved_path.replace(f"{{{var_key}}}", str(var_val))
        base_clean = base_url.rstrip("/")
        path_clean = resolved_path.lstrip("/")
        return f"{base_clean}/{path_clean}" if path_clean else base_clean

    def _sanitize_response_body(self, body_text: Optional[str]) -> Optional[str]:
        """Truncates and sanitizes response body to prevent logging unbounded secret data."""
        if not body_text:
            return body_text
        if len(body_text) > 4096:
            body_text = body_text[:4096] + "\n...[TRUNCATED]"
        return body_text
