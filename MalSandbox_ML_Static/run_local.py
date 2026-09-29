import os, sys
os.environ.setdefault("LOCAL_MODE", "1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
import uvicorn
uvicorn.run("local_server:app", host="127.0.0.1", port=8000, reload=False)
