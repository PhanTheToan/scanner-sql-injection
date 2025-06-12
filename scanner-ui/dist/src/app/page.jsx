"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = Home;
var LogViewer_1 = __importDefault(require("@/components/LogViewer"));
var ReportViewer_1 = __importDefault(require("@/components/ReportViewer"));
function Home() {
    return (<main className="flex min-h-screen flex-col items-center p-8 bg-gray-100">
      <h1 className="text-3xl font-bold mb-8">SQL Injection Scanner Dashboard</h1>
      <LogViewer_1.default />
      <ReportViewer_1.default />
    </main>);
}
