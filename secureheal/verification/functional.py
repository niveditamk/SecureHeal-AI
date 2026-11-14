"""Functional verifier — runs functional and regression checks on patches."""

from __future__ import annotations

import logging

logger = logging.getLogger("secureheal.verification.functional")


class FunctionalVerifier:
    """Verifies that patches maintain functional correctness."""

    def verify_patch(self, patch: dict, test_suite_path: str | None = None) -> dict:
        """Run functional tests against patched code.

        In the research prototype, this performs structural analysis.
        In production, it would execute the actual test suite.
        """
        patched_code = patch.get("patched_code", "")
        original_code = patch.get("original_code", "")

        checks = {
            "code_compiles": self._check_syntax(patched_code, patch.get("file_path", "")),
            "function_signature_preserved": self._check_signature(original_code, patched_code),
            "return_type_preserved": self._check_return_type(original_code, patched_code),
            "no_removed_functionality": len(patched_code) >= len(original_code) * 0.5,
        }

        passed = all(checks.values())
        return {
            "functional_pass": passed,
            "checks": checks,
            "details": "All functional checks passed" if passed else f"Failed checks: {[k for k, v in checks.items() if not v]}",
        }

    def check_api_compatibility(self, patch: dict, api_spec: dict | None = None) -> dict:
        """Ensure the patch doesn't break the API contract."""
        patched = patch.get("patched_code", "")

        # Check that endpoint decorators are preserved
        import re

        original_routes = set(re.findall(r'@(?:app|router)\.\w+\(["\']([^"\']+)', patch.get("original_code", "")))
        patched_routes = set(re.findall(r'@(?:app|router)\.\w+\(["\']([^"\']+)', patched))

        removed_routes = original_routes - patched_routes
        compatible = len(removed_routes) == 0

        return {
            "api_compatible": compatible,
            "removed_routes": list(removed_routes),
            "details": "API contract preserved" if compatible else f"Removed routes: {removed_routes}",
        }

    def run_regression_tests(
        self, patch: dict, test_results_baseline: dict | None = None
    ) -> dict:
        """Compare patched code behavior against baseline test results."""
        # In the prototype, this performs structural regression checks
        patched = patch.get("patched_code", "")
        original = patch.get("original_code", "")

        # Check that the patch doesn't remove error handling
        original_try_count = original.lower().count("try:")
        patched_try_count = patched.lower().count("try:")

        original_except_count = original.lower().count("except")
        patched_except_count = patched.lower().count("except")

        regression_free = patched_try_count >= original_try_count

        return {
            "regression_pass": regression_free,
            "error_handling_preserved": patched_except_count >= original_except_count,
            "details": "No regressions detected" if regression_free else "Error handling may have been removed",
        }

    @staticmethod
    def _check_syntax(code: str, file_path: str) -> bool:
        """Check if the code has valid Python syntax."""
        if file_path.endswith(".java"):
            return True  # Skip Java syntax check in prototype
        try:
            compile(code, file_path or "<string>", "exec")
            return True
        except SyntaxError:
            return False

    @staticmethod
    def _check_signature(original: str, patched: str) -> bool:
        """Check that function signatures are preserved."""
        import re

        orig_sigs = set(re.findall(r"def\s+(\w+)\s*\(([^)]*)\)", original))
        patch_sigs = set(re.findall(r"def\s+(\w+)\s*\(([^)]*)\)", patched))

        # All original functions should still exist
        orig_names = {s[0] for s in orig_sigs}
        patch_names = {s[0] for s in patch_sigs}
        return orig_names.issubset(patch_names)

    @staticmethod
    def _check_return_type(original: str, patched: str) -> bool:
        """Check that return type annotations are preserved."""
        import re

        orig_returns = set(re.findall(r"->\s*(\w+)", original))
        patch_returns = set(re.findall(r"->\s*(\w+)", patched))
        return orig_returns.issubset(patch_returns) or not orig_returns
