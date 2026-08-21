"""Offline smoke for a ZIP-extracted ProofFlow semifinal package."""

from __future__ import annotations

import http.client
import json
import threading
from typing import cast

from demo.server import BIND_HOST, create_server


def main() -> int:
    server = create_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = cast(tuple[str, int], server.server_address)
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request("GET", "/api/bootstrap", headers={"Host": f"{host}:{port}"})
        response = connection.getresponse()
        payload = json.loads(response.read())
        if response.status != 200 or payload.get("ok") is not True:
            raise RuntimeError("loopback bootstrap did not return an OK response")
        boundaries = payload.get("state", {}).get("boundaries", {})
        if boundaries.get("network_bind") != BIND_HOST:
            raise RuntimeError("extracted demo is not bound to the pinned loopback host")
        if boundaries.get("llm_enabled") is not False:
            raise RuntimeError("extracted demo unexpectedly enabled LLM execution")
        if boundaries.get("external_side_effects_enabled") is not False:
            raise RuntimeError("extracted demo unexpectedly enabled external side effects")
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        server.application.close()
        thread.join(timeout=2)
    if thread.is_alive():
        raise RuntimeError("loopback demo thread did not stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
