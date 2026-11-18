"""Private, one-request worker. Never invoke as an agent-facing command."""
import json
from pathlib import Path
import sys

# -I removes the script directory from sys.path; use only our fixed checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_adapter.transport import TransportConfig, _validate, _request


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            return 1
        data = json.loads(raw)
        config = TransportConfig(**data["config"])
        destination = _validate(config, config.endpoint)
        result = _request(config, destination, data["summary"])
        sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # No tracebacks, tokens, hostnames, model responses or raw errors.
        return 1


if __name__ == "__main__":
    sys.exit(main())
