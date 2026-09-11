import json
import re
from typing import Any, Dict, List, Optional


class BrunoResultParser:
    """
    Parses Bruno CLI test execution outputs (JSON reporter / terminal output)
    and maps findings back to attack scenarios and steps.
    """

    def parse_cli_json_output(self, raw_output: str) -> List[Dict[str, Any]]:
        """
        Parses structured JSON output from Bruno CLI if generated with --format json or custom reporter.
        """
        results: List[Dict[str, Any]] = []
        try:
            parsed = json.loads(raw_output)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict) and "results" in parsed:
                return parsed["results"]
        except Exception:
            pass

        # Fallback to line-by-line regex parsing for terminal output
        return self.parse_cli_terminal_output(raw_output)

    def parse_cli_terminal_output(self, stdout: str) -> List[Dict[str, Any]]:
        """
        Parses standard stdout output from Bruno CLI (e.g., '✓ ATK-001 (200ms)', '✕ ATK-002').
        """
        results: List[Dict[str, Any]] = []
        lines = stdout.splitlines()

        for line in lines:
            # Pattern: (✓|✕|PASSED|FAILED) (ATK-\d+) (?:- (.*))? \((\d+)ms\)?
            match = re.search(r"(✓|✕|PASSED|FAILED|PASS|FAIL)\s+([A-Za-z0-9\-_]+)", line)
            if match:
                status_symbol = match.group(1)
                attack_id = match.group(2)
                passed = status_symbol in {"✓", "PASSED", "PASS"}

                duration_match = re.search(r"\((\d+(?:\.\d+)?)\s*ms\)", line)
                duration_ms = float(duration_match.group(1)) if duration_match else 0.0

                results.append({
                    "attack_id": attack_id,
                    "passed": passed,
                    "duration_ms": duration_ms,
                    "raw_line": line.strip()
                })

        return results
