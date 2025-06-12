'use client';

import { useState } from 'react';

export default function ReportViewer() {
  const [reportContent, setReportContent] = useState<string | null>(null);

  const fetchReport = async () => {
    try {
      const response = await fetch('/api/report');
      const html = await response.text();
      setReportContent(html);
    } catch (error) {
      console.error('Error fetching report:', error);
      setReportContent('<p>Error loading report</p>');
    }
  };

  return (
    <div className="mt-6">
      <button
        onClick={fetchReport}
        className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
      >
        View Report
      </button>
      {reportContent && (
        <div
          className="mt-4 p-4 bg-white rounded-lg shadow"
          dangerouslySetInnerHTML={{ __html: reportContent }}
        />
      )}
    </div>
  );
}