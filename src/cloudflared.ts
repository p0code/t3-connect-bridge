import { PluginError } from "@t3tools/plugin-api";
import * as HostProcess from "@t3tools/shared/HostProcess";
import * as Config from "effect/Config";
import * as Digest from "effect/crypto/Digest";
import * as Effect from "effect/Effect";
import * as Hex from "effect/encoding/Hex";
import * as FileSystem from "effect/FileSystem";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as Option from "effect/Option";
import * as Path from "effect/Path";
import * as ChildProcess from "effect/process/ChildProcess";
import * as ChildProcessSpawner from "effect/process/ChildProcessSpawner";
import * as Stream from "effect/Stream";

/** Upstream T3 Code's pin (ddaba134 `relayClient.ts`); checksums are Cloudflare's release files. */
const CLOUDFLARED_VERSION = "2026.10.4";

interface ReleaseAsset {
  readonly url: string;
  readonly sha256: string;
  readonly archive: "binary" | "tgz";
}

const RELEASE = `https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}`;
const WINDOWS_X64: ReleaseAsset = {
  url: `${RELEASE}/cloudflared-windows-amd64.exe`,
  sha256: "411b16d40c8d872243efeb52c550053d00af0a8a97fbb32e730fb8aba429eaa8",
  archive: "binary",
};
const RELEASE_ASSETS: Readonly<Partial<Record<string, ReleaseAsset>>> = {
  "darwin-arm64": {
    url: `${RELEASE}/cloudflared-darwin-arm64.tgz`,
    sha256: "68b6bc4080ac1330234db2a9002d07f98b000537a1bd531a687b660d4160fa7f",
    archive: "tgz",
  },
  "darwin-x64": {
    url: `${RELEASE}/cloudflared-darwin-amd64.tgz`,
    sha256: "f11fbef4207d715892331917dafd437f032cf4b7137ed64dea3008338c1c613d",
    archive: "tgz",
  },
  "linux-arm64": {
    url: `${RELEASE}/cloudflared-linux-arm64`,
    sha256: "2b7203b4fb0ba28a0c1e12f8855ce2c25f76d266a8d5edafac5540b6812acff6",
    archive: "binary",
  },
  "linux-x64": {
    url: `${RELEASE}/cloudflared-linux-amd64`,
    sha256: "ae5e8add7884b0531d66bbca4570d1de491ff6da51e4ebe7eb160cdf241d9e42",
    archive: "binary",
  },
  "win32-x64": WINDOWS_X64,
  // Cloudflare publishes no Windows ARM64 build; x64 runs under emulation.
  "win32-arm64": WINDOWS_X64,
};

export type ConnectorLine = "connected" | "rejected" | "metrics" | "other";

export const METRICS_LINE = /\bStarting metrics server on (127\.0\.0\.1:\d+)\/metrics\b/u;

export function classifyConnectorLine(line: string): ConnectorLine {
  if (/\bRegistered tunnel connection\b/iu.test(line)) return "connected";
  if (
    /\bRegister tunnel error from server side\b/iu.test(line) &&
    /error="(?:Unauthorized:[^"]*|Failed to get tunnel|Tunnel not found|Record for tunnel not found|Invalid tunnel secret)"/iu.test(
      line,
    )
  ) {
    return "rejected";
  }
  return METRICS_LINE.test(line) ? "metrics" : "other";
}

const installError = (message: string) => (cause: unknown) => new PluginError({ message, cause });

/** The pinned cloudflared, downloaded and checksum-verified into the plugin's directory once. */
export const ensureCloudflared = Effect.fn("bridge.cloudflared.ensure")(function* (
  dataDir: string,
) {
  const override = yield* Config.String("T3CODE_CLOUDFLARED_PATH").pipe(Config.option);
  if (Option.isSome(override) && override.value.trim()) return override.value.trim();
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const platform = yield* HostProcess.Platform;
  const arch = yield* HostProcess.Architecture;
  const asset = RELEASE_ASSETS[`${platform}-${arch}`];
  if (asset === undefined) {
    return yield* new PluginError({
      message: `T3 Connect's tunnel has no build for ${platform}-${arch}.`,
    });
  }
  const dir = path.join(dataDir, `cloudflared-${CLOUDFLARED_VERSION}`);
  const executable = path.join(dir, platform === "win32" ? "cloudflared.exe" : "cloudflared");
  if (yield* fs.exists(executable).pipe(Effect.orElseSucceed(() => false))) return executable;

  yield* Effect.logInfo("Downloading cloudflared for T3 Connect", { version: CLOUDFLARED_VERSION });
  const client = yield* HttpClient.HttpClient;
  const bytes = yield* client.get(asset.url).pipe(
    Effect.flatMap(HttpClientResponse.filterStatusOk),
    Effect.flatMap((response) => response.arrayBuffer),
    Effect.map((buffer) => new Uint8Array(buffer)),
    Effect.timeout("10 minutes"),
    Effect.mapError(installError("Could not download cloudflared.")),
  );
  const digest = yield* Digest.Digest;
  const sha256 = Hex.encode(
    yield* digest
      .digest(Digest.sha256, bytes)
      .pipe(Effect.mapError(installError("Could not hash cloudflared."))),
  );
  if (sha256 !== asset.sha256) {
    return yield* new PluginError({ message: "The cloudflared download failed its checksum." });
  }
  const staging = `${dir}.partial`;
  yield* fs.remove(staging, { recursive: true }).pipe(Effect.ignore);
  yield* fs
    .makeDirectory(staging, { recursive: true })
    .pipe(Effect.mapError(installError("Could not install cloudflared.")));
  const stagedExecutable = path.join(staging, path.basename(executable));
  if (asset.archive === "tgz") {
    const archive = path.join(staging, "cloudflared.tgz");
    yield* fs
      .writeFile(archive, bytes)
      .pipe(Effect.mapError(installError("Could not install cloudflared.")));
    const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
    const exitCode = yield* spawner
      .exitCode(ChildProcess.make("tar", ["-xzf", archive, "-C", staging], { shell: false }))
      .pipe(Effect.mapError(installError("Could not unpack cloudflared.")));
    if (exitCode !== 0) return yield* new PluginError({ message: "Could not unpack cloudflared." });
    yield* fs.remove(archive).pipe(Effect.ignore);
  } else {
    yield* fs
      .writeFile(stagedExecutable, bytes)
      .pipe(Effect.mapError(installError("Could not install cloudflared.")));
  }
  yield* fs
    .chmod(stagedExecutable, 0o755)
    .pipe(Effect.mapError(installError("Could not install cloudflared.")));
  yield* fs
    .rename(staging, dir)
    .pipe(Effect.mapError(installError("Could not install cloudflared.")));
  return executable;
});

/** Runs `cloudflared tunnel run` in the caller's scope; closing the scope stops it. */
export const spawnConnector = Effect.fn("bridge.cloudflared.spawn")(
  function* (input: {
    readonly executable: string;
    readonly connectorToken: string;
    readonly onLine: (line: string) => Effect.Effect<void>;
  }) {
    const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
    const child = yield* spawner.spawn(
      ChildProcess.make(
        input.executable,
        [
          "tunnel",
          "--no-autoupdate",
          "--loglevel",
          "info",
          "--output",
          "default",
          "--metrics",
          "127.0.0.1:0",
          "run",
        ],
        {
          detached: false,
          shell: false,
          // The token rides in the environment so it never shows in a process listing.
          env: { ...(yield* HostProcess.Environment), TUNNEL_TOKEN: input.connectorToken },
          stdout: "pipe",
          stderr: "pipe",
        },
      ),
    );
    yield* child.all.pipe(
      Stream.decodeText(),
      Stream.splitLines,
      Stream.map((line) => line.trim()),
      Stream.filter((line) => line.length > 0),
      Stream.runForEach((line) =>
        input.onLine(line.replaceAll(input.connectorToken, "<redacted>")),
      ),
      Effect.ignore,
      Effect.forkScoped,
    );
    return child;
  },
  Effect.mapError(installError("Could not start cloudflared.")),
);
