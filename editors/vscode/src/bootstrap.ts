import * as vscode from "vscode";
import { promises as fsp } from "fs";
import * as crypto from "crypto";
import { execFile } from "child_process";
import * as paths from "./paths";

// Ensures a working secure-vibe binary and a populated data tree are
// available before any scan runs. On first activation (when nothing is
// configured) it downloads a checksum-verified binary into global
// storage, then invokes that binary's own signed `update` to fetch the
// rule data. Subsequent runs short-circuit once both exist.

let inflight: Promise<boolean> | undefined;

export function ensureReady(output: vscode.OutputChannel): Promise<boolean> {
  if (!inflight) {
    inflight = doEnsure(output).finally(() => {
      inflight = undefined;
    });
  }
  return inflight;
}

async function doEnsure(output: vscode.OutputChannel): Promise<boolean> {
  const needBinary =
    !paths.userBinaryPath() && !paths.managedBinaryExists();
  const needData = !paths.userLibraryDir() && !paths.managedDataExists();

  if (!needBinary && !needData) {
    return true;
  }

  if (!paths.autoDownloadEnabled()) {
    // The user opted out of managed installs. We still proceed
    // optimistically (a PATH binary may exist); scans will surface a
    // clear ENOENT / missing-data error if not.
    return true;
  }

  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Setting up Secure-Code Skills",
      cancellable: false,
    },
    async (progress) => {
      try {
        if (needBinary) {
          progress.report({ message: "downloading secure-vibe binary" });
          await downloadBinary(output);
        }
        if (paths.userLibraryDir()) {
          return true;
        }
        if (needData || !paths.managedDataExists()) {
          progress.report({ message: "fetching rule data (signed)" });
          await populateData(output);
        }
        return true;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        output.appendLine(`bootstrap failed: ${msg}`);
        vscode.window
          .showErrorMessage(
            `Secure-Code Skills setup failed: ${msg}`,
            "Show Output"
          )
          .then((c) => c === "Show Output" && output.show(true));
        return false;
      }
    }
  );
}

async function fetchBuffer(url: string): Promise<Buffer> {
  const resp = await fetch(url, { redirect: "follow" });
  if (!resp.ok) {
    throw new Error(`GET ${url} -> HTTP ${resp.status}`);
  }
  const ab = await resp.arrayBuffer();
  return Buffer.from(ab);
}

// downloadBinary fetches the platform binary and its checksum file from
// the release base URL, verifies the SHA-256, and writes it executable
// into managed storage. Mirrors selfupdate.go's asset-naming + checksum
// format exactly.
async function downloadBinary(output: vscode.OutputChannel): Promise<void> {
  const { goos, goarch } = paths.goTarget();
  const base = paths.releaseBaseUrl().replace(/\/+$/, "");
  const assetName = `secure-vibe-${goos}-${goarch}${
    goos === "windows" ? ".exe" : ""
  }`;
  const checksumName = `checksums-${goos}-${goarch}.txt`;

  const binUrl = `${base}/${assetName}`;
  const sumUrl = `${base}/${checksumName}`;
  output.appendLine(`downloading ${binUrl}`);

  const [binBytes, sumText] = await Promise.all([
    fetchBuffer(binUrl),
    fetchBuffer(sumUrl).then((b) => b.toString("utf8")),
  ]);

  const expected = lookupChecksum(sumText, assetName);
  if (!expected) {
    throw new Error(`checksum for ${assetName} not found in ${checksumName}`);
  }
  const got = crypto.createHash("sha256").update(binBytes).digest("hex");
  if (got.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(
      `SHA-256 mismatch for ${assetName}: got ${got} want ${expected}`
    );
  }

  await fsp.mkdir(paths.managedBinDir(), { recursive: true });
  const dest = paths.managedBinaryPath();
  await fsp.writeFile(dest, binBytes, { mode: 0o755 });
  await fsp.chmod(dest, 0o755);
  output.appendLine(`verified + installed ${dest} (sha256 ${got})`);
}

// lookupChecksum parses a sha256sum-style file ("<hex>  <name>") and
// returns the digest for the asset, matching selfupdate.go's parser.
function lookupChecksum(text: string, assetName: string): string | undefined {
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) {
      continue;
    }
    const fields = line.split(/\s+/);
    if (fields.length < 2) {
      continue;
    }
    const name = fields[fields.length - 1].replace(/^\*/, "");
    if (name === assetName) {
      return fields[0].toLowerCase();
    }
  }
  return undefined;
}

// populateData runs `secure-vibe update` into the managed data dir. The
// binary verifies the signed manifest (embedded Ed25519 key) and writes
// the rule tree, so the extension inherits that trust chain rather than
// re-implementing signature verification.
async function populateData(output: vscode.OutputChannel): Promise<void> {
  const bin = paths.managedBinaryExists()
    ? paths.managedBinaryPath()
    : paths.effectiveBinaryPath();
  const dataDir = paths.managedDataDir();
  await fsp.mkdir(dataDir, { recursive: true });
  output.appendLine(`running '${bin} update --path ${dataDir}'`);
  await new Promise<void>((resolve, reject) => {
    execFile(
      bin,
      ["update", "--path", dataDir, "--quiet"],
      { maxBuffer: 64 * 1024 * 1024, env: process.env },
      (err, stdout, stderr) => {
        if (stdout) {
          output.appendLine(String(stdout).trim());
        }
        if (err) {
          reject(new Error(`update failed: ${String(stderr).trim() || err.message}`));
          return;
        }
        resolve();
      }
    );
  });
}
