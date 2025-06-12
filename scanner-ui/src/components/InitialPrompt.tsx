'use client';

import { useState, useEffect } from 'react';
import { Scan, FileText, FileCode, Terminal, Settings, AlertCircle, CheckCircle, Lock, Unlock, XCircle } from 'lucide-react';

export default function InitialPrompt() {
  const [url, setUrl] = useState('http://localhost:8000/');
  const [config, setConfig] = useState('config.yaml');
  const [report, setReport] = useState('report.html');
  const [logfile, setLogfile] = useState('scanner.log');
  const [loglevel, setLoglevel] = useState('INFO');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [errorDetails, setErrorDetails] = useState('');
  const [isConfigEditable, setIsConfigEditable] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Load saved values from localStorage on initial render
  useEffect(() => {
    const savedLogfile = localStorage.getItem('logfile');
    const savedReport = localStorage.getItem('report');
    
    if (savedLogfile) setLogfile(savedLogfile);
    if (savedReport) setReport(savedReport);
  }, []);

  // Update localStorage and dispatch event when logfile changes
  const handleLogfileChange = (newLogfile: string) => {
    setLogfile(newLogfile);
    localStorage.setItem('logfile', newLogfile);
    // Dispatch custom event to notify LogViewer
    window.dispatchEvent(new CustomEvent('logfile-updated', { detail: newLogfile }));
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement> | null) => {
    if (e) {
      e.preventDefault();
    }
    setStatus('Đang chạy...');
    setError('');
    setErrorDetails('');
    setIsSubmitting(true);

    try {
      const response = await fetch('/api/run-scanner', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, config, report, logfile, loglevel }),
      });

      const data = await response.json();
      if (response.ok) {
        setStatus(`Thành công! Log: ${logfile}, Báo cáo: ${report}`);
        localStorage.setItem('report', report);
      } else {
        setError(data.error || 'Lỗi khi chạy scanner');
        setErrorDetails(`Stdout: ${data.stdout || ''}\nStderr: ${data.stderr || ''}`);
        setStatus('');
      }
    } catch (err) {
      setError('Không thể kết nối tới server');
      setErrorDetails(err instanceof Error ? err.message : String(err));
      setStatus('');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleStop = async () => {
    setStatus('Đang dừng...');
    setError('');
    setErrorDetails('');
    setIsSubmitting(true);

    try {
      const response = await fetch('/api/stop-scanner', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      const data = await response.json();
      if (response.ok) {
        setStatus('Scanner đã dừng');
        setIsSubmitting(false);
      } else {
        setError(data.message || 'Lỗi khi dừng scanner');
        setErrorDetails(data.error || '');
        setStatus('');
        setIsSubmitting(false);
      }
    } catch (err) {
      setError('Không thể kết nối tới server');
      setErrorDetails(err instanceof Error ? err.message : String(err));
      setStatus('');
      setIsSubmitting(false);
    }
  };

  const getStatusIcon = () => {
    if (status && status.includes('Thành công')) {
      return <CheckCircle size={20} className="text-green-500" />;
    } else if (status && status.includes('đã dừng')) {
      return <XCircle size={20} className="text-yellow-500" />;
    } else if (error) {
      return <AlertCircle size={20} className="text-red-500" />;
    } else if (status === 'Đang chạy...' || status === 'Đang dừng...') {
      return <Scan size={20} className="text-blue-500 animate-pulse" />;
    }
    return null;
  };

  return (
    <div className="bg-gray-900 text-white p-6 rounded-lg shadow-xl border border-gray-800">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center">
          <Scan className="mr-2 text-blue-400" size={24} />
          <h2 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
            Cấu hình Scanner
          </h2>
        </div>
      </div>

      <div className="space-y-4">
        <div className="bg-gray-800 p-4 rounded-md border border-gray-700">
          <label className="flex items-center text-sm font-medium text-gray-300 mb-2">
            <Settings size={16} className="mr-2 text-blue-400" />
            URL Mục tiêu
          </label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="w-full bg-gray-950 text-white border border-gray-700 rounded-md p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="http://localhost:8000/"
          />
        </div>

        <div className="bg-gray-800 p-4 rounded-md border border-gray-700">
          <div className="flex items-center justify-between mb-2">
            <label className="flex items-center text-sm font-medium text-gray-300">
              <FileCode size={16} className="mr-2 text-purple-400" />
              Config File
            </label>
            <button
              type="button"
              onClick={() => setIsConfigEditable(!isConfigEditable)}
              className="flex items-center text-xs bg-gray-700 hover:bg-gray-600 px-2 py-1 rounded transition-colors"
            >
              {isConfigEditable ? (
                <>
                  <Lock size={14} className="mr-1 text-yellow-400" />
                  <span>Khóa</span>
                </>
              ) : (
                <>
                  <Unlock size={14} className="mr-1 text-green-400" />
                  <span>Mở khóa</span>
                </>
              )}
            </button>
          </div>
          <input
            type="text"
            value={config}
            onChange={(e) => setConfig(e.target.value)}
            className={`w-full bg-gray-950 text-white border ${isConfigEditable ? 'border-blue-500' : 'border-gray-700'} rounded-md p-2 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors`}
            placeholder="config.yaml"
            disabled={!isConfigEditable}
          />
          {!isConfigEditable && (
            <p className="text-xs text-gray-500 mt-1 italic">Mở khóa để chỉnh sửa tên file</p>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-gray-800 p-4 rounded-md border border-gray-700">
            <label className="flex items-center text-sm font-medium text-gray-300 mb-2">
              <FileText size={16} className="mr-2 text-green-400" />
              Report File
            </label>
            <input
              type="text"
              value={report}
              onChange={(e) => setReport(e.target.value)}
              className="w-full bg-gray-950 text-white border border-gray-700 rounded-md p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="report.html"
            />
          </div>

          <div className="bg-gray-800 p-4 rounded-md border border-gray-700">
            <label className="flex items-center text-sm font-medium text-gray-300 mb-2">
              <Terminal size={16} className="mr-2 text-yellow-400" />
              Log File
            </label>
            <input
              type="text"
              value={logfile}
              onChange={(e) => handleLogfileChange(e.target.value)}
              className="w-full bg-gray-950 text-white border border-gray-700 rounded-md p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="scanner.log"
            />
          </div>
        </div>

        <div className="bg-gray-800 p-4 rounded-md border border-gray-700">
          <label className="flex items-center text-sm font-medium text-gray-300 mb-2">
            <Settings size={16} className="mr-2 text-red-400" />
            Log Level
          </label>
          <select
            value={loglevel}
            onChange={(e) => setLoglevel(e.target.value)}
            className="w-full bg-gray-950 text-white border border-gray-700 rounded-md p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="DEBUG">DEBUG</option>
            <option value="INFO">INFO</option>
            <option value="WARNING">WARNING</option>
            <option value="ERROR">ERROR</option>
          </select>
        </div>

        <div className="flex space-x-4">
          <button
            onClick={() => handleSubmit(null)}
            disabled={isSubmitting}
            className={`flex-1 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-md py-3 hover:from-blue-700 hover:to-purple-700 transition-all flex items-center justify-center ${isSubmitting ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isSubmitting ? (
              <>
                <Scan className="animate-spin mr-2" size={18} />
                Đang chạy...
              </>
            ) : (
              <>
                <Scan className="mr-2" size={18} />
                Chạy Scanner
              </>
            )}
          </button>
          {isSubmitting && (
            <button
              onClick={handleStop}
              className="flex-1 bg-gradient-to-r from-red-600 to-red-800 text-white rounded-md py-3 hover:from-red-700 hover:to-red-900 transition-all flex items-center justify-center"
            >
              <XCircle className="mr-2" size={18} />
              Dừng Scanner
            </button>
          )}
        </div>
      </div>

      {(status || error) && (
        <div className={`mt-6 p-4 rounded-md border ${status ? 'bg-green-900/20 border-green-800' : 'bg-red-900/20 border-red-800'}`}>
          <div className="flex items-center">
            {getStatusIcon()}
            <span className={`ml-2 ${status ? 'text-green-400' : 'text-red-400'} font-medium`}>
              {status || error}
            </span>
          </div>
          {errorDetails && (
            <pre className="mt-3 p-3 bg-gray-950 border border-gray-800 rounded text-sm text-gray-300 overflow-x-auto">
              {errorDetails}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}