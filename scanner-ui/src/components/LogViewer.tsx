'use client';

import { useEffect, useState } from 'react';
import { Terminal, Activity, AlertCircle, Info, CheckCircle, X, RefreshCw } from 'lucide-react';

export default function LogViewer() {
  const [logs, setLogs] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState('');
  const [logfile, setLogfile] = useState('scanner.log');

  // Theo dõi thay đổi của logfile trong localStorage và sự kiện tùy chỉnh
  useEffect(() => {
    const updateLogfile = () => {
      if (typeof window !== 'undefined') {
        const storedLogfile = localStorage.getItem('logfile') || 'scanner.log';
        setLogfile(storedLogfile);
      }
    };

    // Cập nhật ngay khi mount
    updateLogfile();

    // Lắng nghe sự kiện logfile-updated từ InitialPrompt
    const handleLogfileUpdated = (event: CustomEvent) => {
      const newLogfile = event.detail || localStorage.getItem('logfile') || 'scanner.log';
      setLogfile(newLogfile);
    };

    window.addEventListener('logfile-updated', handleLogfileUpdated as EventListener);

    return () => {
      window.removeEventListener('logfile-updated', handleLogfileUpdated as EventListener);
    };
  }, []);

  type LogEntry = {
    id: number;
    text: string;
    type: 'info' | 'error' | 'warning' | 'success';
  };

  const parsedLogs = logs
    ? logs.split('\n').map((line, index) => {
        let type: LogEntry['type'] = 'info';
        if (line.toLowerCase().includes('error')) type = 'error';
        if (line.toLowerCase().includes('warn')) type = 'warning';
        if (line.toLowerCase().includes('success')) type = 'success';

        return { id: index, text: line, type };
      })
    : [];

  const filteredLogs = parsedLogs.filter((log) =>
    log.text.toLowerCase().includes(filter.toLowerCase())
  );

  useEffect(() => {
    setIsLoading(true);
    const ws = new WebSocket('ws://localhost:8081');

    ws.onopen = () => {
      setIsConnected(true);
      setIsLoading(false);
      ws.send(JSON.stringify({ logfile }));
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'log') {
          setLogs((prevLogs) => prevLogs + message.data);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      console.log('WebSocket connection closed');
    };

    ws.onerror = () => {
      setIsConnected(false);
      setIsLoading(false);
    };

    return () => {
      ws.close();
    };
  }, [logfile]);

  useEffect(() => {
    if (autoScroll) {
      const logContainer = document.getElementById('log-container');
      if (logContainer) {
        logContainer.scrollTop = logContainer.scrollHeight;
      }
    }
  }, [logs, autoScroll]);

  const handleReconnect = () => {
    window.location.reload();
  };

  const handleClearLogs = () => {
    setLogs('');
  };

  const renderLogLine = (log: LogEntry) => {
    let icon;
    let textColor = 'text-gray-300';

    switch (log.type) {
      case 'error':
        icon = <AlertCircle size={16} className="text-red-500 mr-2 flex-shrink-0" />;
        textColor = 'text-red-400';
        break;
      case 'warning':
        icon = <Info size={16} className="text-yellow-500 mr-2 flex-shrink-0" />;
        textColor = 'text-yellow-400';
        break;
      case 'success':
        icon = <CheckCircle size={16} className="text-green-500 mr-2 flex-shrink-0" />;
        textColor = 'text-green-400';
        break;
      default:
        icon = <Terminal size={16} className="text-blue-500 mr-2 flex-shrink-0" />;
    }

    return (
      <div key={log.id} className={`flex items-start py-1 border-b border-gray-800 ${textColor}`}>
        {icon}
        <span className="font-mono text-sm break-all">{log.text}</span>
      </div>
    );
  };

  return (
    <div className="bg-gray-900 text-white p-6 rounded-lg shadow-xl border border-gray-800">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <Terminal className="mr-2 text-blue-400" size={24} />
          <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
            Real-Time Logs ({logfile})
          </h2>
        </div>
        <div className="flex items-center space-x-2">
          <span
            className={`inline-flex items-center px-2 py-1 rounded-full text-xs ${
              isConnected ? 'bg-green-900 text-green-400' : 'bg-red-900 text-red-400'
            }`}
          >
            <span
              className={`w-2 h-2 mr-1 rounded-full ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}
            ></span>
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
          <button
            onClick={handleReconnect}
            className="p-2 rounded-full hover:bg-gray-800 transition-colors"
            title="Reconnect"
          >
            <RefreshCw size={18} className={`text-gray-400 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <div className="flex items-center justify-between mb-4">
        <div className="relative w-64">
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter logs..."
            className="w-full bg-gray-800 text-white border border-gray-700 rounded-md py-1 px-3 pl-8 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <div className="absolute left-2 top-2">
            <Activity size={16} className="text-gray-400" />
          </div>
          {filter && (
            <button
              onClick={() => setFilter('')}
              className="absolute right-2 top-2"
              title="Clear filter"
            >
              <X size={16} className="text-gray-400 hover:text-white" />
            </button>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <label className="flex items-center space-x-2 text-sm text-gray-400">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="form-checkbox h-4 w-4 text-blue-500"
            />
            <span>Auto-scroll</span>
          </label>
          <button
            onClick={handleClearLogs}
            className="px-3 py-1 bg-gray-800 hover:bg-gray-700 text-sm rounded-md transition-colors"
          >
            Clear logs
          </button>
        </div>
      </div>

      <div
        id="log-container"
        className="bg-gray-950 rounded-md p-4 h-96 overflow-y-auto border border-gray-800 shadow-inner"
      >
        {filteredLogs.length > 0 ? (
          filteredLogs.map(renderLogLine)
        ) : (
          <div className="flex items-center justify-center h-full text-gray-500 italic">
            {isLoading ? 'Connecting to server...' : 'No logs available'}
          </div>
        )}
      </div>

      <div className="mt-2 text-xs text-gray-500 flex justify-between">
        <span>
          {filteredLogs.length} entries {filter && `(filtered from ${parsedLogs.length})`}
        </span>
        <span>{isConnected ? `Listening on ws://localhost:8081 for ${logfile}` : 'Connection closed'}</span>
      </div>
    </div>
  );
}