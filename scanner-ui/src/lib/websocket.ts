import { WebSocketServer } from "ws";
import fs from "fs";
import path from "path";

export function startWebSocketServer() {
  const wss = new WebSocketServer({ port: 8081 });

  wss.on("connection", (ws) => {
    console.log("Client connected to WebSocket");

    ws.on("message", (message) => {
      const { logfile } = JSON.parse(message.toString());
      if (!logfile) return;

      const projectDir = "/media/ptt/New Volume/HUST/2024.2/project2/scanner-sql-injection";
      const logFilePath = path.resolve(projectDir, logfile);

      console.log("Watching logfile:", logFilePath);

      // Gửi nội dung log ban đầu
      if (fs.existsSync(logFilePath)) {
        const initialContent = fs.readFileSync(logFilePath, "utf8");
        ws.send(JSON.stringify({ type: "log", data: initialContent }));
      } else {
        ws.send(JSON.stringify({ type: "log", data: "Log file not found" }));
      }

      // Theo dõi thay đổi file
      fs.watchFile(logFilePath, (curr, prev) => {
        if (curr.mtime > prev.mtime) {
          const content = fs.readFileSync(logFilePath, "utf8");
          ws.send(JSON.stringify({ type: "log", data: content }));
        }
      });
    });

    ws.on("close", () => {
      console.log("Client disconnected");
    });
  });

  console.log("WebSocket server running on ws://localhost:8081");
}