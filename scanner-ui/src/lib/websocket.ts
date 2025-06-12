import { WebSocketServer } from "ws";
import fs from "fs";
import path from "path";

export function startWebSocketServer() {
  const wss = new WebSocketServer({ port: 8081 });
  const lastSentContent: { [key: string]: string } = {};

  wss.on("connection", (ws) => {
    console.log("Client connected to WebSocket");

    ws.on("message", (message) => {
      try {
        console.log("Received message:", message.toString());
        const { logfile } = JSON.parse(message.toString());
        if (!logfile) return;

        const projectDir = "/media/ptt/New Volume/HUST/2024.2/project2/scanner-sql-injection";
        const logFilePath = path.resolve(projectDir, logfile);

        console.log("Watching logfile:", logFilePath);

        if (fs.existsSync(logFilePath)) {
          const initialContent = fs.readFileSync(logFilePath, "utf8");
          lastSentContent[logFilePath] = initialContent;
          ws.send(JSON.stringify({ type: "log", data: initialContent }));
        } else {
          lastSentContent[logFilePath] = "";
          ws.send(JSON.stringify({ type: "log", data: "Log file not found" }));
        }

        fs.watchFile(logFilePath, { interval: 1000 }, (curr, prev) => {
          if (curr.mtime > prev.mtime) {
            try {
              const currentContent = fs.readFileSync(logFilePath, "utf8");
              const lastContent = lastSentContent[logFilePath] || "";
              if (currentContent !== lastContent) {
                const newContent = currentContent.slice(lastContent.length);
                if (newContent.trim()) {
                  console.log("Sending new log content:", newContent);
                  ws.send(JSON.stringify({ type: "log", data: newContent }));
                }
                lastSentContent[logFilePath] = currentContent;
              }
            } catch (error) {
              console.error("Error reading log file:", error);
              ws.send(JSON.stringify({ type: "log", data: "Error reading log file" }));
            }
          }
        });
      } catch (error) {
        console.error("Error processing WebSocket message:", error);
      }
    });

    ws.on("close", () => {
      console.log("Client disconnected");
    });
  });

  console.log("WebSocket server running on ws://localhost:8081");
}