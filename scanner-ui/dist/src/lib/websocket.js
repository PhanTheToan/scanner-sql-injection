"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.startWebSocketServer = startWebSocketServer;
var ws_1 = require("ws");
var fs_1 = __importDefault(require("fs"));
var path_1 = __importDefault(require("path"));
var logFilePath = path_1.default.resolve('/media/ptt/New Volume/HUST/2024.2/project2/scanner-sql-injection/scanner.log');
function startWebSocketServer() {
    var wss = new ws_1.WebSocketServer({ port: 8080 });
    wss.on('connection', function (ws) {
        console.log('Client connected to WebSocket');
        // Send initial log content
        if (fs_1.default.existsSync(logFilePath)) {
            var initialContent = fs_1.default.readFileSync(logFilePath, 'utf8');
            ws.send(JSON.stringify({ type: 'log', data: initialContent }));
        }
        // Watch for file changes
        fs_1.default.watchFile(logFilePath, function (curr, prev) {
            if (curr.mtime > prev.mtime) {
                var content = fs_1.default.readFileSync(logFilePath, 'utf8');
                ws.send(JSON.stringify({ type: 'log', data: content }));
            }
        });
        ws.on('close', function () {
            console.log('Client disconnected');
        });
    });
    console.log('WebSocket server running on ws://localhost:8080');
}
