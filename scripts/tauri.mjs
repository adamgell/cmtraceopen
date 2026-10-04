import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const selectionKey = "CMTRACE_TAURI_BUNDLE_TARGETS";
const profile = fileURLToPath(new URL("../src-tauri/tauri.appimage.conf.json", import.meta.url));
const nonAppImageFormats = new Set(["deb", "rpm", "nsis", "msi", "app", "dmg", "updater"]);

// Read only the desktop CLI's selection flags. Leave validation, config parsing
// and every original argv token to Tauri, including the Cargo tail after `--`.
export function tauriInvocation(args, inheritedEnv = process.env, platform = process.platform, arch = process.arch) {
  const env = { ...inheritedEnv };
  delete env[selectionKey];
  let command = 0;
  while (args[command] === "--verbose" || /^-v+$/.test(args[command] ?? "")) command++;
  if (!["build", "bundle"].includes(args[command])) return { args: [...args], env };

  let bundles = null;
  let target;
  let skip = false;
  for (let i = command + 1; i < args.length && args[i] !== "--"; i++) {
    const arg = args[i];
    let option;
    let attached;
    if (arg.startsWith("--")) {
      const equals = arg.indexOf("=");
      option = equals < 0 ? arg.slice(2) : arg.slice(2, equals);
      if (equals >= 0) attached = arg.slice(equals + 1);
    } else if (arg.startsWith("-")) {
      // clap accepts flag clusters followed by an option and its attached value.
      for (let j = 1; j < arg.length; j++) {
        if ("hV".includes(arg[j])) skip = true;
        if ("btcfr".includes(arg[j])) {
          option = { b: "bundles", t: "target", c: "config", f: "features", r: "runner" }[arg[j]];
          if (j + 1 < arg.length) attached = arg.slice(j + 1).replace(/^=/, "");
          break;
        }
        if (!"vdhV".includes(arg[j])) break; // Unknown flags remain Tauri errors.
      }
    }
    if (["no-bundle", "help", "version"].includes(option)) skip = true;
    if (option === "bundles" || option === "features") {
      const values = attached === undefined ? [] : attached.split(",");
      while (i + 1 < args.length && !args[i + 1].startsWith("-")) values.push(...args[++i].split(","));
      if (option === "bundles") (bundles ??= []).push(...values);
    } else if (["target", "config", "runner"].includes(option)) {
      const value = attached ?? (args[i + 1] && !args[i + 1].startsWith("-") ? args[++i] : undefined);
      if (option === "target") target = value;
    }
  }
  if (skip) return { args: [...args], env };
  env[selectionKey] = JSON.stringify(bundles);
  // Unknown/custom target strings remain conservative; Tauri validates them and
  // the hook's authoritative TAURI_ENV_PLATFORM/ARCH gate still applies.
  const linuxX64 = target
    ? (!/^[\w]+-[\w]+-[\w-]+$/.test(target) || (target.startsWith("x86_64-") && target.includes("-linux-")))
    : platform === "linux" && arch === "x64";
  if (!linuxX64 || (bundles !== null && bundles.every((format) => nonAppImageFormats.has(format)))) {
    return { args: [...args], env };
  }
  return { args: [...args.slice(0, command + 1), "--config", profile, ...args.slice(command + 1)], env };
}

export async function runTauri(args, cli = createRequire(import.meta.url).resolve("@tauri-apps/cli/tauri.js")) {
  const invocation = tauriInvocation(args);
  const child = spawn(process.execPath, [cli, ...invocation.args], { env: invocation.env, stdio: "inherit" });
  const forwardInterrupt = () => child.kill("SIGINT");
  const forwardTermination = () => child.kill("SIGTERM");
  process.on("SIGINT", forwardInterrupt);
  process.on("SIGTERM", forwardTermination);
  try {
    const [code, signal] = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve([code, signal]));
    });
    process.exitCode = code ?? 1;
    if (signal) {
      process.removeListener("SIGINT", forwardInterrupt);
      process.removeListener("SIGTERM", forwardTermination);
      process.kill(process.pid, signal);
    }
  } finally {
    process.removeListener("SIGINT", forwardInterrupt);
    process.removeListener("SIGTERM", forwardTermination);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runTauri(process.argv.slice(2));
}
