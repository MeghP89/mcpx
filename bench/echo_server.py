import json
import sys

TOOLS = [{
    "name": "echo",
    "description": "Echo text back",
    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
}]

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg["method"]
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "bench", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    else:
        result = {"content": [{"type": "text", "text": msg["params"]["arguments"]["text"]}]}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
