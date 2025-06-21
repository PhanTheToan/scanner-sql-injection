import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

const reportFilePath = path.resolve('/home/toan_phan/scanner-sql-injection/report.html');

export async function GET() {
  try {
    if (!fs.existsSync(reportFilePath)) {
      return new NextResponse('Report file not found', { status: 404 });
    }
    const content = fs.readFileSync(reportFilePath, 'utf8');
    return new NextResponse(content, {
      headers: { 'Content-Type': 'text/html' },
    });
  } catch (error) {
    console.error('Error reading report file:', error);
    return new NextResponse('Internal server error', { status: 500 });
  }
}