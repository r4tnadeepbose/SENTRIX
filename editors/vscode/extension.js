// SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
"use strict";

const vscode = require("vscode");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

let diagnostics;
let output;

function resolveHome() {
  const cfg = vscode.workspace.getConfiguration("sentrix");
  const configured = (cfg.get("home") || "").trim();
  if (configured) {
    return configured;
  }
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    return "";
  }
  const workspaceDir = folders[0].uri.fsPath;
  // Default layout: the workspace is opened at editors/vscode, so the SENTRIX
  // root sits two levels up. Fall back to the workspace folder itself.
  const twoUp = path.resolve(workspaceDir, "..", "..");
  if (fs.existsSync(path.join(twoUp, "run.py"))) {
    return twoUp;
  }
  if (fs.existsSync(path.join(workspaceDir, "run.py"))) {
    return workspaceDir;
  }
  return twoUp;
}

function severityFor(level) {
  switch ((level || "").toLowerCase()) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function scanFile(uri) {
  const home = resolveHome();
  if (!home) {
    output.appendLine("No workspace folder open; cannot resolve the SENTRIX home.");
    return;
  }
  const python = vscode.workspace.getConfiguration("sentrix").get("python") || "python";
  const script = path.join(home, "run.py");
  const file = uri.fsPath;
  const args = [script, "scan", "--json", "--no-store", file];
  output.appendLine(`> ${python} ${args.join(" ")}`);

  const child = spawn(python, args, { cwd: home });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("error", (err) => {
    output.appendLine(`Failed to start the scanner: ${err.message}`);
    vscode.window.showErrorMessage(`SENTRIX: ${err.message}`);
  });
  child.on("close", (code) => {
    if (stderr.trim()) {
      output.appendLine(stderr.trim());
    }
    let findings;
    try {
      findings = JSON.parse(stdout);
    } catch (err) {
      output.appendLine(`Could not parse scanner output (exit ${code}): ${err.message}`);
      return;
    }
    if (!Array.isArray(findings)) {
      output.appendLine("Scanner output was not a JSON array; skipping.");
      return;
    }
    const doc = vscode.workspace.textDocuments.find(
      (d) => d.uri.toString() === uri.toString()
    );
    const items = findings.map((f) => {
      const lineNo = Math.max(0, (f.line || 1) - 1);
      let range;
      if (doc && lineNo < doc.lineCount) {
        range = doc.lineAt(lineNo).range;
      } else {
        range = new vscode.Range(lineNo, 0, lineNo, Number.MAX_SAFE_INTEGER);
      }
      const message = `${f.title || f.detector_id || "Secret detected"}: ${f.secret_masked || "masked"}`;
      const diag = new vscode.Diagnostic(range, message, severityFor(f.severity));
      diag.source = "SENTRIX";
      diag.code = f.detector_id || undefined;
      return diag;
    });
    diagnostics.set(uri, items);
    output.appendLine(`${items.length} finding(s) in ${file}`);
  });
}

function activate(context) {
  output = vscode.window.createOutputChannel("SENTRIX");
  diagnostics = vscode.languages.createDiagnosticCollection("sentrix");
  context.subscriptions.push(output, diagnostics);

  context.subscriptions.push(
    vscode.commands.registerCommand("sentrix.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanFile(editor.document.uri);
      } else {
        vscode.window.showInformationMessage("SENTRIX: open a file to scan.");
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => scanFile(doc.uri))
  );

  output.appendLine("SENTRIX extension activated.");
}

function deactivate() {}

module.exports = { activate, deactivate };