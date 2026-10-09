import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
BACKEND_DIR = os.path.join(PARENT_DIR, "backend")

for path in [BACKEND_DIR, PARENT_DIR]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

try:
    from app import app as _backend_app
except ImportError:
    from backend.app import app as _backend_app

app = _backend_app
application = _backend_app
handler = _backend_app

