"use strict";
'use client';
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = LogViewer;
var react_1 = require("react");
function LogViewer() {
    var _a = (0, react_1.useState)(''), logs = _a[0], setLogs = _a[1];
    (0, react_1.useEffect)(function () {
        var ws = new WebSocket('ws://localhost:8081');
        ws.onmessage = function (event) {
            var message = JSON.parse(event.data);
            if (message.type === 'log') {
                setLogs(message.data);
            }
        };
        ws.onclose = function () {
            console.log('WebSocket connection closed');
        };
        return function () {
            ws.close();
        };
    }, []);
    return (<div className="bg-gray-900 text-white p-4 rounded-lg h-96 overflow-y-auto">
      <h2 className="text-xl font-bold mb-2">Real-Time Logs</h2>
      <pre className="whitespace-pre-wrap">{logs || 'No logs available'}</pre>
    </div>);
}
