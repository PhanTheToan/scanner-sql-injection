import { WebSocketServer } from 'ws';
import fs from 'fs';
import path from 'path';

const logFilePath = path.resolve('/media/ptt/New Volume/HUST/2024.2/project2/scanner-sql-injection/scanner.log');

export function startWebSocketServer() {
  const wss = new WebSocketServer({ port: 8081 });

  wss.on('connection', (ws) => {
    console.log('Client connected to WebSocket');

    // Send initial log content
    if (fs.existsSync(logFilePath)) {
      const initialContent = fs.readFileSync(logFilePath, 'utf8');
      ws.send(JSON.stringify({ type: 'log', data: initialContent }));
    }

    // Watch for file changes
    fs.watchFile(logFilePath, (curr, prev) => {
      if (curr.mtime > prev.mtime) {
        const content = fs.readFileSync(logFilePath, 'utf8');
        ws.send(JSON.stringify({ type: 'log', data: content }));
      }
    });

    ws.on('close', () => {
      console.log('Client disconnected');
    });
  });

  console.log('WebSocket server running on ws://localhost:8080');
}