"""Security tests can be collected by the top-level pytest run too.

Make sure the plugin dir is on sys.path so `import adapter` resolves
the same way it does for the unit-test suite.
"""

import sys
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PLUGIN_DIR))
