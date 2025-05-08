import { NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";

const execPromise = promisify(exec);

export async function POST() {
  try {
    // Tìm và dừng tiến trình Python chạy src.scanner
    const command = "pkill -f 'python.*src\\.scanner'";

    let stdout = "";
    let stderr = "";

    try {
      const result = await execPromise(command, {
        shell: "/bin/bash",
      });
      stdout = result.stdout;
      stderr = result.stderr;
    } catch (error: any) {
      stdout = error.stdout || "";
      stderr = error.stderr || "";
    }

    // Xác định thông điệp dựa trên stderr
    const message = stderr.includes("no process found") || !stderr
      ? "Không tìm thấy tiến trình scanner hoặc đã dừng"
      : "Scanner đã dừng";

    // Chỉ trả về thông điệp, không trả stdout/stderr
    return NextResponse.json({ message }, { status: 200 });
  } catch (error: any) {
    console.error("Unexpected error in stop-scanner:", error);
    return NextResponse.json(
      {
        message: "Không thể dừng scanner",
        error: error.message,
      },
      { status: 500 }
    );
  }
}