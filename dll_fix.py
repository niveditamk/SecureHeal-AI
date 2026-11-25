"""Fix the ormsgpack DLL blocking issue."""
import sys
import subprocess

print("=== SecureHeal-AI DLL Fix Tool ===\n")

# Method 1: Try reinstalling ormsgpack
print("Method 1: Reinstalling ormsgpack...")
result = subprocess.run(
    [sys.executable, '-m', 'pip', 'install', '--force-reinstall', 'ormsgpack'],
    capture_output=True, text=True
)
print(f"  stdout: {result.stdout[-200:]}")
print(f"  stderr: {result.stderr[-200:]}")
print(f"  returncode: {result.returncode}")
if result.returncode == 0:
    print("  ✓ Reinstallation attempted")
else:
    print("  ✗ Reinstallation failed")

# Method 2: Try importing after reinstall
print("\nMethod 2: Testing import after reinstall...")
try:
    import ormsgpack
    print(f"  ✓ ormsgpack imported successfully (version: {getattr(ormsgpack, '__version__', 'unknown')})")
except ImportError as e:
    print(f"  ✗ import failed: {e}")

# Method 3: Try langgraph import
print("\nMethod 3: Testing langgraph import...")
try:
    from secureheal.orchestrator.state import SecureHealState
    print(f"  ✓ SecureHealState imported successfully")
except Exception as e:
    print(f"  ✗ import failed: {e}")

print("\n=== DLL Fix Complete ===")