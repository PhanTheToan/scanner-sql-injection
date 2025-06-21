import { NextResponse } from "next/server";
import { exec } from "child_process";
import { promisify } from "util";
import fs from "fs";

const execPromise = promisify(exec);

export async function POST(request: Request) {
  try {
    const body = await request.json();
    console.log("Request body:", body);

    const { url, config, report, logfile, loglevel } = body;
    console.log("Parsed parameters:", { url, config, report, logfile, loglevel });

    // Kiểm tra tham số config
    if (!config) {
      console.log("Config parameter is missing or undefined");
      return NextResponse.json(
        { error: "Config parameter is required" },
        { status: 400 }
      );
    }

    // Project directory (đường dẫn mới)
    const projectDir = "/home/toan_phan/scanner-sql-injection";
    const configPath = `${projectDir}/${config}`;
    console.log("Config path:", configPath);

    // Kiểm tra file
    const configExists = fs.existsSync(configPath);
    console.log("Config file exists:", configExists);

    if (!configExists) {
      console.log("Config file check failed:", configPath);
      return NextResponse.json(
        { error: `Config file ${config} does not exist at ${configPath}` },
        { status: 400 }
      );
    }

    // Lệnh Python
    const pythonPath = `${projectDir}/.venv/bin/python`;
    const command = `${pythonPath} -m src.scanner --url '${url || 'http://localhost:8000'}' --config '${config}' --report '${report || 'report.html'}' --loglevel '${loglevel || 'DEBUG'}' --logfile '${logfile || 'scanner.log'}'`;

    console.log("Running command:", command);

    const { stdout, stderr } = await execPromise(command, {
      cwd: projectDir,
      shell: "/bin/bash",
    });

    console.log("Command output:", { stdout, stderr });
    return NextResponse.json({ message: "Scanner ran successfully", stdout, stderr });
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