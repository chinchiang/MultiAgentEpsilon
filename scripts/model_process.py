#!/usr/bin/env python3
"""擁有者完成程序群組的持久化登記前，子程序不得執行。

Do not execute a child until its owner has durably registered its group."""
import os
import sys

if __name__ == '__main__':
    # stdin 只有握手閘門；AWS payload 使用封存的繼承 descriptor。 / stdin contains only the gate; AWS payloads use a sealed inherited descriptor.
    # 擁有者若在登記前死亡，管線關閉；EOF 表示不可執行。 / An owner killed before registration closes this pipe: EOF means no exec.
    if os.read(0, 1) != b'G':
        raise SystemExit(1)
    os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
