"""Security verifier — checks patches for new vulnerabilities and CWE fix validation."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger("secureheal.verification.security")

# Dangerous patterns to check in patched code
DANGEROUS_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "python": [
        (r"eval\s*\(", "Use of eval() — potential code injection"),
        (r"exec\s*\(", "Use of exec() — potential code injection"),
        (r"pickle\.loads?\s*\(", "Use of pickle — insecure deserialization"),
        (r"subprocess\..*shell\s*=\s*True", "Shell=True in subprocess — command injection risk"),
        (r"os\.system\s*\(", "os.system() — command injection risk"),
        (r'f["\'].*\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)', "f-string in SQL — injection risk"),
        (r"\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE)", "str.format in SQL — injection risk"),
        (r"password\s*=\s*[\"'][^\"']+[\"']", "Hardcoded password"),
        (r"api_key\s*=\s*[\"'][^\"']+[\"']", "Hardcoded API key"),
    ],
    "java": [
        (r"Runtime\.getRuntime\(\)\.exec\(", "Runtime.exec — command injection risk"),
        (r"ObjectInputStream", "ObjectInputStream — deserialization risk"),
        (r'Statement.*execute\(.*\+', "String concatenation in SQL — injection risk"),
        (r"password\s*=\s*\"[^\"]+\"", "Hardcoded password"),
        (r"apiKey\s*=\s*\"[^\"]+\"", "Hardcoded API key"),
    ],
}


class SecurityVerifier:
    """Verifies patches don't introduce new security weaknesses."""

    def run_static_analysis(self, patched_code: str, language: str) -> dict:
        """Simulate a static analysis scan on patched code."""
        findings: list[dict] = []
        patterns = DANGEROUS_PATTERNS.get(language, DANGEROUS_PATTERNS["python"])

        for pattern, description in patterns:
            matches = list(re.finditer(pattern, patched_code, re.IGNORECASE))
            for match in matches:
                line_num = patched_code[: match.start()].count("\n") + 1
                findings.append({
                    "rule": pattern,
                    "description": description,
                    "line": line_num,
                    "snippet": patched_code.splitlines()[line_num - 1].strip() if line_num <= len(patched_code.splitlines()) else "",
                    "severity": "high",
                })

        return {
            "security_pass": len(findings) == 0,
            "findings_count": len(findings),
            "findings": findings,
            "details": "No security issues found" if not findings else f"{len(findings)} security issues detected",
        }

    def check_new_vulnerabilities(
        self, original_code: str, patched_code: str
    ) -> dict:
        """Detect vulnerabilities that exist in the patch but not in the original."""
        language = "java" if "class " in original_code and "public " in original_code else "python"
        patterns = DANGEROUS_PATTERNS.get(language, DANGEROUS_PATTERNS["python"])

        original_issues = set()
        patched_issues = set()

        for pattern, description in patterns:
            if re.search(pattern, original_code, re.IGNORECASE):
                original_issues.add(description)
            if re.search(pattern, patched_code, re.IGNORECASE):
                patched_issues.add(description)

        new_issues = patched_issues - original_issues
        fixed_issues = original_issues - patched_issues

        return {
            "new_vulnerabilities": list(new_issues),
            "fixed_vulnerabilities": list(fixed_issues),
            "net_improvement": len(fixed_issues) - len(new_issues),
            "security_pass": len(new_issues) == 0,
            "details": (
                f"Fixed {len(fixed_issues)} issues, introduced {len(new_issues)} new issues"
            ),
        }

    def validate_cwe_fix(self, patch: dict, target_cwe: str) -> dict:
        """Verify that the specific CWE vulnerability is addressed by the patch."""
        patched = patch.get("patched_code", "")
        original = patch.get("original_code", "")

        validators: dict[str, callable] = {
            "CWE-89": self._validate_sqli_fix,
            "CWE-79": self._validate_xss_fix,
            "CWE-862": self._validate_auth_fix,
            "CWE-918": self._validate_ssrf_fix,
            "CWE-22": self._validate_path_traversal_fix,
            "CWE-78": self._validate_cmdi_fix,
            "CWE-502": self._validate_deser_fix,
            "CWE-798": self._validate_hardcoded_creds_fix,
        }

        validator = validators.get(target_cwe)
        if validator:
            return validator(original, patched)

        return {"cwe_fixed": False, "details": f"No validator for {target_cwe}"}

    # --- CWE-specific validators ---

    @staticmethod
    def _validate_sqli_fix(original: str, patched: str) -> dict:
        has_parameterized = any(kw in patched for kw in ["?", "%s", ":param", "bindparam", "PreparedStatement"])
        has_concat_removed = not any(kw in patched.lower() for kw in ["f'select", 'f"select', "+ user", "format("])
        fixed = has_parameterized or has_concat_removed
        return {"cwe_fixed": fixed, "details": "Parameterized queries detected" if fixed else "SQL injection pattern may remain"}

    @staticmethod
    def _validate_xss_fix(original: str, patched: str) -> dict:
        has_escaping = any(kw in patched for kw in ["html.escape", "escape(", "Encode.forHtml", "markupsafe", "autoescape"])
        fixed = has_escaping
        return {"cwe_fixed": fixed, "details": "Output escaping detected" if fixed else "XSS fix not confirmed"}

    @staticmethod
    def _validate_auth_fix(original: str, patched: str) -> dict:
        has_auth = any(kw in patched.lower() for kw in ["depends(", "authorize", "permission", "role", "authenticated", "current_user"])
        fixed = has_auth and not any(kw in original.lower() for kw in ["depends(", "authorize", "permission"])
        return {"cwe_fixed": fixed or has_auth, "details": "Authorization check added" if fixed else "Auth fix not confirmed"}

    @staticmethod
    def _validate_ssrf_fix(original: str, patched: str) -> dict:
        has_validation = any(kw in patched.lower() for kw in ["allowed_hosts", "whitelist", "allowlist", "urlparse", "isSiteLocal"])
        return {"cwe_fixed": has_validation, "details": "URL validation detected" if has_validation else "SSRF fix not confirmed"}

    @staticmethod
    def _validate_path_traversal_fix(original: str, patched: str) -> dict:
        has_path_check = any(kw in patched.lower() for kw in [".resolve()", ".normalize()", "realpath", "startswith", "canonical"])
        return {"cwe_fixed": has_path_check, "details": "Path validation detected" if has_path_check else "Path traversal fix not confirmed"}

    @staticmethod
    def _validate_cmdi_fix(original: str, patched: str) -> dict:
        removed_shell = "shell=True" not in patched.lower() or "shell=True" in original.lower()
        uses_list_args = "subprocess.run([" in patched or "ProcessBuilder" in patched
        return {"cwe_fixed": removed_shell and uses_list_args, "details": "Safe command execution detected" if uses_list_args else "Command injection fix not confirmed"}

    @staticmethod
    def _validate_deser_fix(original: str, patched: str) -> dict:
        removed_unsafe = "pickle.load" not in patched.lower() and "ObjectInputStream" not in patched
        uses_safe = any(kw in patched for kw in ["json.loads", "json.load", "ObjectMapper", "JsonParser"])
        return {"cwe_fixed": removed_unsafe and uses_safe, "details": "Safe deserialization detected" if uses_safe else "Deserialization fix not confirmed"}

    @staticmethod
    def _validate_hardcoded_creds_fix(original: str, patched: str) -> dict:
        uses_env = any(kw in patched for kw in ["os.environ", "os.getenv", "System.getenv", "dotenv", "settings."])
        no_hardcoded = not re.search(r'(?:password|secret|api_key)\s*=\s*["\'][^"\']{3,}["\']', patched, re.IGNORECASE)
        return {"cwe_fixed": uses_env and no_hardcoded, "details": "Credentials externalized" if uses_env else "Hardcoded credentials may remain"}
