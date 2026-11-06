#!/usr/bin/env python3
"""Framework-neutral agent caller. Run from a supported Linux ordinary user."""
import argparse
import json
from pathlib import Path
import signal
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--enclio", default="enclio")
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()
    # Keep the result outside the writable workspace. Stream business I/O.
    with tempfile.TemporaryDirectory(prefix="agent-result-") as directory:
        result = Path(directory) / "result.json"
        process = subprocess.Popen([
            args.enclio, "run", "--workspace", args.workspace, "--timeout", "30",
            "--result", str(result), "--", "/bin/sh", "-c", "echo agent task; ls -la /workspace",
        ])
        try:
            process.wait()
        except KeyboardInterrupt:
            process.send_signal(signal.SIGTERM)
            process.wait()
        if not result.exists() or not result.stat().st_size:
            raise SystemExit(f"No result; CLI exited {process.returncode}")
        data = json.loads(result.read_text())
        print(json.dumps(data, ensure_ascii=False))
        raise SystemExit(0 if data["status"] == "exited" and data["exit_code"] == 0 else 1)


if __name__ == "__main__":
    main()
