# usage: python3 bench/client.py <calls> <server command...>
import json
import statistics
import subprocess
import sys
import time

n = int(sys.argv[1])
proc = subprocess.Popen(sys.argv[2:], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, text=True, bufsize=1)


def send(msg):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", **msg}) + "\n")
    proc.stdin.flush()


def rpc(id, method, params):
    send({"id": id, "method": method, "params": params})
    while True:
        resp = json.loads(proc.stdout.readline())
        if resp.get("id") == id:
            return resp


start = time.perf_counter()
rpc(0, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bench", "version": "1"}})
send({"method": "notifications/initialized"})
rpc(1, "tools/list", {})
startup_ms = (time.perf_counter() - start) * 1000

lat = []
for i in range(n):
    start = time.perf_counter()
    resp = rpc(i + 2, "tools/call", {"name": "echo", "arguments": {"text": "hello world " * 8}})
    lat.append((time.perf_counter() - start) * 1e6)
    assert "result" in resp, resp

lat.sort()
print(f"startup {startup_ms:.1f}ms  p50 {lat[n // 2]:.0f}us  p99 {lat[int(n * .99)]:.0f}us  "
      f"mean {statistics.mean(lat):.0f}us  {n / (sum(lat) / 1e6):.0f} calls/s")
proc.stdin.close()
proc.wait(timeout=5)
