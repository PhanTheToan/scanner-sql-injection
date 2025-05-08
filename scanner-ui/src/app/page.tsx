import LogViewer from '@/components/LogViewer';
import ReportViewer from '@/components/ReportViewer';

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center p-8 bg-gray-100">
      <h1 className="text-3xl font-bold mb-8">SQL Injection Scanner Dashboard</h1>
      <LogViewer />
      <ReportViewer />
    </main>
  );
}