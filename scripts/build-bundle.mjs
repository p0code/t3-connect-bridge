#!/usr/bin/env node
/**
 * Builds the p0code shop release bundle for @t3tools/plugin-t3-connect-bridge:
 *   dist/plugin.mjs
 *   dist/manifest.json
 *   dist/backup-<version>.tgz  (root entries: manifest.json, plugin.mjs)
 *   dist/backup-<version>.tgz.sha256
 *   dist/SHA256SUMS.txt
 *
 * Host runtime packages (`effect`, `@t3tools/plugin-api`, `@t3tools/contracts`,
 * `@effect/platform-node*`) stay external because p0code's installer symlinks its own
 * copies into the installed plugin directory. `@t3tools/shared` is inlined instead,
 * since the installer does not link it.
 *
 * The build fails unless the bundle's default export is a Plugin whose manifest declares
 * `apiVersion: 1`, because `importInstalledBundle` refuses anything else.
 *
 * Usage:
 *   P0CODE_REPO=/path/to/p0code node scripts/build-bundle.mjs
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import util from "node:util";

const BUNDLE_NAME = "t3-connect-bridge";
const PLUGIN_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const OUT_DIR = path.join(PLUGIN_DIR, "dist");
// What the installer links into an installed plugin; everything here must stay external.
const HOST_EXTERNALS = [
  "effect",
  "@t3tools/plugin-api",
  "@t3tools/contracts",
  "@effect/platform-node",
  "@effect/platform-node-shared",
];

function findHostRoot() {
  const candidates = [process.env.P0CODE_REPO, path.resolve(PLUGIN_DIR, "../..")].filter(Boolean);
  for (const root of candidates) {
    if (existsSync(path.join(root, "packages/plugin-api/package.json"))) return root;
  }
  throw new Error(
    "Could not locate a p0code checkout. Set P0CODE_REPO=/path/to/p0code or mount this repo at plugins/<name>.",
  );
}

function hostNodeModules(hostRoot) {
  return [
    path.join(hostRoot, "apps/server/node_modules"),
    path.join(hostRoot, "packages/plugin-api/node_modules"),
    path.join(hostRoot, "node_modules"),
    path.join(hostRoot, "node_modules/.pnpm/node_modules"),
  ].filter((dir) => existsSync(dir));
}

function findEsbuild(hostRoot) {
  const candidates = [
    process.env.ESBUILD_PATH,
    path.join(PLUGIN_DIR, "node_modules/esbuild/lib/main.js"),
    path.join(hostRoot, "node_modules/.pnpm/node_modules/esbuild/lib/main.js"),
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (existsSync(candidate)) return createRequire(import.meta.url)(candidate);
  }
  throw new Error("Could not locate esbuild. Set ESBUILD_PATH or run inside a p0code checkout.");
}

/** Resolves the host packages the installer links, exactly as apps/server/src/plugins/installer.ts does. */
function resolveHostPackageDirs(hostRoot) {
  const searchRoots = hostNodeModules(hostRoot);
  const resolved = {};
  for (const name of HOST_EXTERNALS) {
    for (const root of searchRoots) {
      const candidate = path.join(root, ...name.split("/"));
      const pkgPath = path.join(candidate, "package.json");
      if (!existsSync(pkgPath)) continue;
      if (JSON.parse(readFileSync(pkgPath, "utf8")).name === name) {
        resolved[name] = realpathSync(candidate);
        break;
      }
    }
    if (!resolved[name]) throw new Error(`Could not resolve host external ${name} from ${hostRoot}`);
  }
  return resolved;
}

function linkHostPackages(targetDir, packageDirs) {
  for (const [name, sourceDir] of Object.entries(packageDirs)) {
    const dest = path.join(targetDir, "node_modules", ...name.split("/"));
    mkdirSync(path.dirname(dest), { recursive: true });
    symlinkSync(sourceDir, dest, "dir");
  }
}

const sha256File = (filePath) => createHash("sha256").update(readFileSync(filePath)).digest("hex");

const pkg = JSON.parse(readFileSync(path.join(PLUGIN_DIR, "package.json"), "utf8"));
const hostRoot = findHostRoot();
const esbuild = findEsbuild(hostRoot);

rmSync(OUT_DIR, { recursive: true, force: true });
mkdirSync(OUT_DIR, { recursive: true });

const bundlePath = path.join(OUT_DIR, "plugin.mjs");
await esbuild.build({
  entryPoints: [path.join(PLUGIN_DIR, "src/index.ts")],
  outfile: bundlePath,
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  nodePaths: hostNodeModules(hostRoot),
  external: [...HOST_EXTERNALS, "effect/*", "@effect/platform-node/*", "node:*"],
});

// Load the built plugin.mjs the way the installer will and assert its contract before publishing.
const stageDir = path.join(os.tmpdir(), `p0-${BUNDLE_NAME}-bundle-verify-${process.pid}-${Date.now()}`);
mkdirSync(stageDir, { recursive: true });
let manifest;
try {
  const hostPackages = resolveHostPackageDirs(hostRoot);
  linkHostPackages(stageDir, hostPackages);
  const stagedBundle = path.join(stageDir, "plugin.mjs");
  writeFileSync(stagedBundle, readFileSync(bundlePath));
  const exported = (await import(`${pathToFileURL(stagedBundle).href}?t=${Date.now()}`)).default;
  if (
    typeof exported !== "object" ||
    exported === null ||
    !("manifest" in exported) ||
    !("start" in exported)
  ) {
    throw new Error(
      "Bundled plugin.mjs has no default export shaped like a Plugin. Add `export default <plugin>` to src/index.ts.",
    );
  }
  const effectMod = await import(
    pathToFileURL(path.join(hostPackages.effect, "dist/Effect.js")).href
  );
  if (!effectMod.isEffect(exported.start)) {
    throw new Error("Bundled plugin.mjs default.start is not an Effect.");
  }
  manifest = exported.manifest;
  if (manifest.apiVersion !== 1) {
    throw new Error(
      `Manifest apiVersion is ${JSON.stringify(manifest.apiVersion)}; add \`apiVersion: 1\` to the plugin manifest.`,
    );
  }
  if (manifest.version !== pkg.version) {
    throw new Error(
      `Manifest version (${manifest.version}) disagrees with package.json (${pkg.version}).`,
    );
  }
  const roundTripped = JSON.parse(JSON.stringify(manifest));
  if (!util.isDeepStrictEqual(roundTripped, manifest)) {
    throw new Error("Manifest is not clean JSON round-trip equal.");
  }
} finally {
  rmSync(stageDir, { recursive: true, force: true });
}

const manifestPath = path.join(OUT_DIR, "manifest.json");
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

const tarballName = `${BUNDLE_NAME}-${manifest.version}.tgz`;
const tarballPath = path.join(OUT_DIR, tarballName);
execFileSync("tar", ["-czf", tarballPath, "-C", OUT_DIR, "manifest.json", "plugin.mjs"], {
  env: { ...process.env, COPYFILE_DISABLE: "1" },
  stdio: "inherit",
});

// The installer reads root entries, so reject `./` prefixes and AppleDouble files.
const listing = execFileSync("tar", ["-tzf", tarballPath], { encoding: "utf8" })
  .trim()
  .split(/\r?\n/)
  .sort();
if (!util.isDeepStrictEqual(listing, ["manifest.json", "plugin.mjs"])) {
  throw new Error(`Unexpected tarball entries: ${JSON.stringify(listing)}`);
}

const tarballSha = sha256File(tarballPath);
writeFileSync(path.join(OUT_DIR, `${tarballName}.sha256`), `${tarballSha}  ${tarballName}\n`);
writeFileSync(
  path.join(OUT_DIR, "SHA256SUMS.txt"),
  [
    `${tarballSha}  ${tarballName}`,
    `${sha256File(bundlePath)}  plugin.mjs`,
    `${sha256File(manifestPath)}  manifest.json`,
    "",
  ].join("\n"),
);

console.log(`Built ${tarballPath}`);
console.log(`  size:   ${readFileSync(tarballPath).byteLength} bytes`);
console.log(`  sha256: ${tarballSha}`);
console.log(`  apiVersion: ${manifest.apiVersion}`);
