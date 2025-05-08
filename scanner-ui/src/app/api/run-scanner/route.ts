import { NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";

const execPromise = promisify(exec);

export async function POST(request: Request) {
  try {
    const { url, config, report, logfile, loglevel } = await request.json();

    // Xác thực tham số
    if (!url || !config || !report || !logfile || !loglevel) {
      return NextResponse.json({ error: "Thiếu tham số bắt buộc" }, { status: 400 });
    }

    // Đường dẫn dự án
    const projectDir = "/media/ptt/New Volume/HUST/2024.2/project2/scanner-sql-injection";

    // Kiểm tra sự tồn tại của file config.yaml
    const fs = require("fs");
    const configPath = path.resolve(projectDir, config);
    console.log("Checking config path:", configPath);
    if (!fs.existsSync(configPath)) {
      return NextResponse.json({ error: `File config ${config} không tồn tại tại ${configPath}` }, { status: 400 });
    }

    // Sử dụng Python trong venv trực tiếp
    const pythonPath = path.resolve(projectDir, ".venv/bin/python");
    const command = `"${pythonPath}" -m src.scanner --url "${url}" --config "${config}" --report "${report}" --loglevel "${loglevel}" --logfile "${logfile}"`;

    console.log("Running command:", command);

    // Chạy lệnh
    const { stdout, stderr } = await execPromise(command, {
      cwd: projectDir,
      shell: "/bin/bash",
    });

    return NextResponse.json({ message: "Scanner chạy thành công", stdout, stderr });
  } catch (error: any) {
    console.error("Error executing command:", error);
    return NextResponse.json(
      {
        error: `Command failed: ${error.message}`,
        stdout: error.stdout || "",
        stderr: error.stderr || "",
      },
      { status: 500 }
    );
  }
}