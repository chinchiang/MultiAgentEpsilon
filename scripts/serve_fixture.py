#!/usr/bin/env python3
"""僅以 loopback 啟動修正版；資料庫 schema 須先由 smoke runner 建立。

Loopback fixed variant only. Schema must have been created by the smoke runner."""
import argparse
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import uvicorn
from fixture_app.app import create_app, database_url

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True,
                        help='合成 fixture schema 名稱 / synthetic fixture schema name')
    parser.add_argument("--port", type=int, default=18765,
                        help='loopback 連接埠 / loopback port')
    args = parser.parse_args()
    uvicorn.run(create_app(database_url(), args.schema), host="127.0.0.1", port=args.port,
                access_log=False, log_level="error")
