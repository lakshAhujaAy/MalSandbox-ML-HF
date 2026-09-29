import json
from collections import defaultdict
from typing import Dict, List

from fastapi import WebSocket
from utils.logger import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections per job_id and a global broadcast feed."""

    def __init__(self):
        self._connections: Dict[str, List[WebSocket]] = defaultdict(list)

    async def connect(self, channel: str, websocket: WebSocket):
        await websocket.accept()
        self._connections[channel].append(websocket)
        logger.debug(f"WS connected: channel={channel}")

    def disconnect(self, channel: str, websocket: WebSocket):
        self._connections[channel].remove(websocket)
        logger.debug(f"WS disconnected: channel={channel}")

    async def broadcast(self, channel: str, data: dict):
        """Send to all subscribers of a specific channel AND the global feed."""
        payload = json.dumps(data)
        dead = []
        for ws in self._connections.get(channel, []):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append((channel, ws))

        # Also push to global feed
        for ws in self._connections.get("__feed__", []):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(("__feed__", ws))

        for ch, ws in dead:
            try:
                self._connections[ch].remove(ws)
            except ValueError:
                pass
