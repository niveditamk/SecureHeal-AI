"""Security constraints — CWE-specific repair constraint definitions."""

from __future__ import annotations

import logging

logger = logging.getLogger("secureheal.repair.constraints")

# Pre-defined constraint sets for the 8 target CWEs
_CWE_CONSTRAINTS: dict[str, list[str]] = {
    "CWE-89": [
        "Must use parameterized queries or prepared statements",
        "Must not concatenate user input into SQL strings",
        "Must validate and sanitize all user inputs used in database queries",
        "Must use ORM methods or query builders where available",
    ],
    "CWE-79": [
        "Must encode/escape all user-supplied output in HTML context",
        "Must use framework-provided auto-escaping mechanisms",
        "Must set appropriate Content-Type and X-Content-Type-Options headers",
        "Must not use innerHTML or dangerouslySetInnerHTML with user input",
    ],
    "CWE-862": [
        "Must add authorization check before accessing protected resources",
        "Must verify user roles and permissions against required access level",
        "Must return 403 Forbidden for unauthorized access attempts",
        "Must not rely solely on client-side authorization checks",
    ],
    "CWE-918": [
        "Must validate and whitelist allowed destination URLs/hosts",
        "Must block requests to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1)",
        "Must not follow redirects to untrusted destinations",
        "Must enforce URL scheme restrictions (allow only https where possible)",
    ],
    "CWE-22": [
        "Must canonicalize and resolve file paths before access",
        "Must validate that resolved paths remain within the allowed base directory",
        "Must reject path traversal sequences (../, ..\\, %2e%2e)",
        "Must not use user input directly in file system operations",
    ],
    "CWE-78": [
        "Must not pass user input to OS commands or shell interpreters",
        "Must use safe APIs with argument lists instead of shell execution",
        "Must whitelist allowed command arguments if shell invocation is unavoidable",
        "Must never use shell=True with user-controlled input",
    ],
    "CWE-502": [
        "Must not deserialize untrusted data with unsafe deserializers (pickle, shelve, ObjectInputStream)",
        "Must use safe serialization formats (JSON, Protocol Buffers) for untrusted input",
        "Must validate and constrain deserialized object types against an allowlist",
        "Must implement integrity checks on serialized data where applicable",
    ],
    "CWE-798": [
        "Must move all credentials to environment variables or a secret manager",
        "Must not hardcode passwords, API keys, tokens, or cryptographic keys in source code",
        "Must ensure credential files are excluded from version control (.gitignore)",
        "Must use configuration injection patterns for secrets",
    ],
}


class SecurityConstraints:
    """Manages CWE-specific security constraints for patch validation."""

    def get_constraints_for_cwe(self, cwe_id: str) -> list[str]:
        """Return the security constraints applicable to a given CWE."""
        constraints = _CWE_CONSTRAINTS.get(cwe_id, [])
        if not constraints:
            logger.warning("No predefined constraints for %s — using generic set", cwe_id)
            constraints = [
                "Must address the identified vulnerability",
                "Must not introduce new security weaknesses",
                "Must preserve existing functionality",
            ]

        # Universal constraints always apply
        constraints.extend([
            "Patch must be minimal — change only what is necessary to fix the vulnerability",
            "Patch must preserve existing API contracts and response formats",
            "Patch must be compatible with the service's existing dependencies",
        ])
        return constraints

    def validate_patch_constraints(
        self, patch: dict, constraints: list[str]
    ) -> dict:
        """Check if a patch satisfies all specified constraints.

        Returns a summary dict with per-constraint results.
        """
        results = []
        patched_code = patch.get("patched_code", "")
        original_code = patch.get("original_code", "")

        for constraint in constraints:
            passed = self._check_constraint(constraint, patched_code, original_code)
            results.append({"constraint": constraint, "passed": passed})

        return {
            "patch_file": patch.get("file_path", "unknown"),
            "total_constraints": len(results),
            "passed": sum(1 for r in results if r["passed"]),
            "failed": sum(1 for r in results if not r["passed"]),
            "all_satisfied": all(r["passed"] for r in results),
            "details": results,
        }

    @staticmethod
    def _check_constraint(constraint: str, patched: str, original: str) -> bool:
        """Heuristic check for a single constraint against patched code."""
        cl = constraint.lower()
        pl = patched.lower()

        # Parameterized queries
        if "parameterized" in cl:
            bad_patterns = ["f'select", 'f"select', "+ user", ".format(", "% ("]
            return not any(bp in pl for bp in bad_patterns)

        # Escape/encode output
        if "escape" in cl or "encode" in cl:
            good_patterns = ["html.escape", "escape(", "encode.", "markupsafe", "autoescape"]
            return any(gp in pl for gp in good_patterns) or "xss" not in pl

        # Authorization check
        if "authorization" in cl and "check" in cl:
            good_patterns = ["depends(", "authorized", "permission", "role", "@login_required", "@preauthorize"]
            return any(gp in pl for gp in good_patterns)

        # Environment variables
        if "environment variable" in cl:
            good_patterns = ["os.environ", "os.getenv", "system.getenv", "dotenv", "settings."]
            return any(gp in pl for gp in good_patterns)

        # Path validation
        if "canonicalize" in cl or "resolve" in cl:
            good_patterns = [".resolve()", ".normalize()", "realpath", "canonical"]
            return any(gp in pl for gp in good_patterns)

        # Shell=True
        if "shell=true" in cl:
            return "shell=true" not in pl

        # Default: assume passed (LLM verification will do deeper analysis)
        return True
