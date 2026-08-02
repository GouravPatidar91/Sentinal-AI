import json
from typing import List
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accepts a new WebSocket connection and adds it to the active list."""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Removes a closed WebSocket connection from the active list."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcasts a JSON message to all active WebSocket clients."""
        disconnected_clients = []
        for connection in self.active_connections:
            try:
                # Send text message (JSON-encoded)
                await connection.send_text(json.dumps(message))
            except Exception as e:
                # Log socket error and mark client for removal
                print(f"Failed to send websocket message to a client: {e}")
                disconnected_clients.append(connection)
                
        # Clean up dead connections
        for client in disconnected_clients:
            self.disconnect(client)

# Global instance of ConnectionManager
manager = ConnectionManager()
