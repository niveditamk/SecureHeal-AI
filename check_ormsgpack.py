import sys
sys.path.insert(0, '.')

# Check what attributes ormsgpack has
try:
    import ormsgpack
    attrs = [a for a in dir(ormgpack) if not a.startswith('__')]
    print("ormsgpack attributes:")
    for a in attrs:
        print(f"  {a}")
except ImportError as e:
    print(f"Cannot import ormsgpack: {e}")