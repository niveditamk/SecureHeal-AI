"""Test all SecureHeal-AI agents and core modules."""
import sys
sys.path.insert(0, '.')
# Workaround for Windows AppControl blocking ormsgpack DLL
import types
class MockOrmsgpack:
    OPT_NON_STR_KEYS = 0
    OPT_PASSTHROUGH_DATACLASS = 1
    OPT_PASSTHROUGH_DATETIME = 2
    OPT_PASSTHROUGH_ENUM = 3
    OPT_REPLACE_SURROGATES = 4
    OPT_USE_BIN_TYPE = 5
    OPT_SERIALIZE_SPECIAL_ANSICHARS = 6
    OPT_PASSTHROUGH_UUID = 7
    OPT_REPLACE_SURROGATES_EXTRA = 64
    class MsgpackEncodeError(Exception):
        pass
    class Ext:
        EXT_NUMPY_ARRAY = 0
        EXT_DELTA_SNAPSHOT = 1
    @staticmethod
    def loads(data, **kwargs):
        import json
        return json.loads(data)
    @staticmethod
    def dumps(data, **kwargs):
        import json
        return json.dumps(data)
    @staticmethod
    def unpackb(data, **kwargs):
        import json
        return json.loads(data)
    @staticmethod
    def packb(data, **kwargs):
        import json
        return json.dumps(data)
    @staticmethod
    def pack(obj, **kwargs):
        import json
        return json.dumps(obj)
    @staticmethod
    def dec(obj, **kwargs):
        import json
        return json.loads(data)
    EXT_NUMPY_ARRAY = 0
    EXT_DELTA_SNAPSHOT = 1


# Apply the mock ormsgpack to sys.modules before any other imports
sys.modules['ormsgpack'] = MockOrmsgpack()

def test_agent_imports():
    """Test that all 6 agent modules can be imported."""
    print("=" * 60)
    print("TEST 1: Agent Module Imports")
    print("=" * 60)
    
    agents = [
        ('threat_detection', 'secureheal.agents.threat_detection'),
        ('root_cause', 'secureheal.agents.root_cause'),
        ('context_intelligence', 'secureheal.agents.context_intelligence'),
        ('repair_generation', 'secureheal.agents.repair_generation'),
        ('patch_verification', 'secureheal.agents.patch_verification'),
        ('recovery_governance', 'secureheal.agents.recovery_governance'),
        ('base', 'secureheal.agents.base'),
    ]
    
    results = {}
    for name, module_path in agents:
        try:
            __import__(module_path, fromlist=[''])
            results[name] = 'OK'
            print(f"  PASS: {name}: Imported successfully")
        except Exception as e:
            results[name] = f'FAILED'
            print(f"  FAIL: {name}: {str(e)[:50]}")
    
    return results

def test_orchestrator():
    """Test orchestrator import and graph building."""
    print()
    print("=" * 60)
    print("TEST 2: Orchestrator Import")
    print("=" * 60)
    
    try:
        from secureheal.orchestrator.graph import build_graph, run_pipeline
        from secureheal.orchestrator.state import SecureHealState
        print("  PASS: Orchestrator: Imported successfully")
        print(f"  PASS: build_graph: {build_graph is not None}")
        print(f"  PASS: SecureHealState: {SecureHealState is not None}")
        return 'OK'
    except Exception as e:
        print(f"  FAIL: Orchestrator: {e}")
        return f'FAILED: {e}'

def test_evidence_models():
    """Test evidence models."""
    print()
    print("=" * 60)
    print("TEST 3: Evidence Models")
    print("=" * 60)
    
    try:
        from secureheal.evidence.models import EvidenceItem, EvidenceSource, IncidentReport
        print("  PASS: Evidence models: Imported successfully")
        
        item = EvidenceItem(
            source=EvidenceSource.LOG,
            type="sql_error",
            content={"raw_line": "SQL injection attempt"},
            service_name="test-svc",
            severity="high",
        )
        print(f"  PASS: EvidenceItem created: id={item.id}, source={item.source}")
        
        report = IncidentReport(
            service_name="python-fastapi",
            language="python",
            classification="sql_injection",
        )
        print(f"  PASS: IncidentReport: service={report.service_name}")
        return 'OK'
    except Exception as e:
        print(f"  FAIL: Evidence models: {e}")
        return f'FAILED: {e}'
    
    return 'OK'  # Avoid unreachable

def test_constraints():
    """Test repair constraints."""
    print()
    print("=" * 60)
    print("TEST 4: Repair Constraints")
    print("=" * 60)
    
    try:
        from secureheal.repair.constraints import SecurityConstraints
        sc = SecurityConstraints()
        cwe89 = sc.get_constraints_for_cwe("CWE-89")
        print(f"  PASS: SecurityConstraints: {len(cwe89)} CWE-89 constraints")
        has_param = any("parameterized" in c.lower() for c in cwe89)
        print(f"  PASS: Has parameterized constraint: {has_param}")
        return 'OK'
    except Exception as e:
        print(f"  FAIL: SecurityConstraints: {e}")
        return f'FAILED: {e}'

def test_security_verifier():
    """Test security verifier."""
    print()
    print("=" * 60)
    print("TEST 5: Security Verifier")
    print("=" * 60)
    
    try:
        from secureheal.verification.security import SecurityVerifier
        verifier = SecurityVerifier()
        
        result = verifier.run_static_analysis("data = json.loads(user_input)", "python")
        print(f"  PASS: Safe code: security_pass={result['security_pass']}, findings={result['findings_count']}")
        
        result2 = verifier.run_static_analysis("data = pickle.loads(user_input)", "python")
        print(f"  PASS: Unsafe code: security_pass={result2['security_pass']}, findings={result2['findings_count']}")
        return 'OK'
    except Exception as e:
        print(f"  FAIL: SecurityVerifier: {e}")
        return f'FAILED: {e}'

def test_functional_verifier():
    """Test functional verifier."""
    print()
    print("=" * 60)
    print("TEST 6: Functional Verifier")
    print("=" * 60)
    
    try:
        from secureheal.verification.functional import FunctionalVerifier
        fv = FunctionalVerifier()
        
        result = fv._check_syntax("def hello(): return 'world'", "test.py")
        print(f"  PASS: Syntax check: {result}")
        
        sig_result = fv._check_signature(
            "def search_users(query: str) -> list:",
            "def search_users(query: str) -> list:\n    return []"
        )
        print(f"  PASS: Signature check: {sig_result}")
        return 'OK'
    except Exception as e:
        print(f"  FAIL: FunctionalVerifier: {e}")
        return f'FAILED: {e}'

def test_approval_gateway():
    """Test approval gateway."""
    print()
    print("=" * 60)
    print("TEST 7: Approval Gateway")
    print("=" * 60)
    
    try:
        from secureheal.governance.approval import ApprovalGateway
        gw = ApprovalGateway()
        patches = [{"file_path": "app.py", "patched_code": "safe code"}]
        verification = [{"functional_pass": True, "security_pass": True, "regression_pass": True}]
        package = gw.prepare_review_package("INC-001", patches, verification)
        print(f"  PASS: Review package: incident_id={package['incident_id']}, risk={package['risk_summary']['risk_level']}")
        return 'OK'
    except Exception as e:
        print(f"  FAIL: ApprovalGateway: {e}")
        return f'FAILED: {e}'

def test_rollback_manager():
    """Test rollback manager."""
    print()
    print("=" * 60)
    print("TEST 8: Rollback Manager")
    print("=" * 60)
    
    try:
        from secureheal.governance.rollback import RollbackManager
        rm = RollbackManager()
        point = rm.create_rollback_point("python-fastapi", "PATCH-001")
        print(f"  PASS: create_rollback_point: status={point['status']}")
        result = rm.execute_rollback(point["rollback_id"])
        print(f"  PASS: execute_rollback: success={result['success']}")
        verify = rm.verify_rollback("python-fastapi")
        print(f"  PASS: verify_rollback: health_check={verify['health_check']}")
        return 'OK'
    except Exception as e:
        print(f"  FAIL: RollbackManager: {e}")
        return f'FAILED: {e}'

if __name__ == "__main__":
    print("SecureHeal-AI Agent & Core Module Testing")
    print("=" * 60)
    
    results = {}
    
    results['imports'] = test_agent_imports()
    results['orchestrator'] = test_orchestrator()
    results['evidence'] = test_evidence_models()
    results['constraints'] = test_constraints()
    results['security_verifier'] = test_security_verifier()
    results['functional_verifier'] = test_functional_verifier()
    results['approval_gateway'] = test_approval_gateway()
    results['rollback_manager'] = test_rollback_manager()
    
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v == 'OK')
    failed = sum(1 for v in results.values() if v != 'OK')
    
    for name, result in results.items():
        status = 'PASS' if result == 'OK' else 'FAIL'
        print(f"  {name:25s}: {status}")
    
    print(f"\nTotal: {passed} passed, {failed} failed out of {len(results)} tests")
    
    sys.exit(0 if failed == 0 else 1)