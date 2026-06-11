import pathlib
import sys

# Ensure the src/ layout is importable when running pytest from the repo root.
sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
