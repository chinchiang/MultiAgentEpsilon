#!/usr/bin/env python3
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixture_app.app import database_url
from security_harness.authorization import run_authorization

if __name__ == "__main__":
    print(json.dumps(run_authorization(database_url(), sys.argv[1])))
