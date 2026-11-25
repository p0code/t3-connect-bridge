import {
  PluginContext,
  PluginError,
  type PluginRouteHandler,
  type PluginServices,
} from "@t3tools/plugin-api";
import * as Clock from "effect/Clock";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as DateTime from "effect/DateTime";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as Option from "effect/Option";
import * as Ref from "effect/Ref";
import * as Schema from "effect/Schema";
import * as Schedule from "effect/Schedule";
import * as Scope from "effect/Scope";
import * as Semaphore from "effect/Semaphore";

import { BridgeConfig, type BridgeConfigPatch, type BridgeStatus } from "./actions.ts";
import {
  classifyConnectorLine,
  ensureCloudflared,
  METRICS_LINE,
  spawnConnector,
} from "./cloudflared.ts";
import {
  generateKeyPair,
  hasBoundedLifetime,
  hasExactScope,
  isValidPublicKey,
  KeyPair,
  normalizeIssuer,
  signJwt,
  unverifiedIssuedAt,
  verifyJwt,
} from "./jwt.ts";
import {
  type DeviceAuthorization,
  pollDeviceToken,
  refreshIfNeeded,
  startDeviceAuthorization,
  StoredToken,
} from "./oauth.ts";
import {
  HealthProofPayload,
  LinkChallengeResponse,
  LinkResponse,
  ManagedEndpointRuntimeConfig,
  MintCredentialProofPayload,
  OkResponse,
  ProofRequest,
  RELAY_HEALTH_REQUEST_TYP,
  RELAY_HEALTH_RESPONSE_TYP,
  RELAY_LINK_PROOF_TYP,
  RELAY_MINT_REQUEST_TYP,
  RELAY_MINT_RESPONSE_TYP,
} from "./relayProtocol.ts";
import { normalizeRelayUrl, parseLocalOrigin, relayRequest, RelayRequestError } from "./relay.ts";

export const StoredLink = Schema.Struct({
  relayUrl: Schema.String,
  relayIssuer: Schema.String,
  cloudUserId: Schema.String,
  environmentCredential: Schema.String,
  cloudMintPublicKey: Schema.String,
  endpointRuntime: Schema.NullOr(ManagedEndpointRuntimeConfig),
});
export type StoredLink = typeof StoredLink.Type;

const KEYS = {
  config: "config",
  token: "token",
  link: "link",
  signingKey: "signing-key",
  wantLinked: "want-linked",
} as const;

const DEFAULT_CONFIG = Schema.decodeSync(BridgeConfig)({});
const decodeProofRequest = Schema.decodeUnknownOption(ProofRequest);

const RECOVERY_COOLDOWN = Duration.minutes(2);
const RECOVERY_MAX_COOLDOWN = Duration.minutes(30);
const REJECTIONS_BEFORE_RELINK = 4;

const ConnectorConfigBody = Schema.Struct({
  config: Schema.Struct({
    ingress: Schema.optional(
      Schema.NullOr(Schema.Array(Schema.Struct({ hostname: Schema.optional(Schema.String) }))),
    ),
  }),
});

interface RuntimeState {
  readonly pendingSignIn: { readonly verificationUrl: string; readonly userCode: string } | null;
  readonly tunnel: BridgeStatus["tunnel"];
  readonly hostname: string | null;
  readonly error: string | null;
}

const isPluginError = Schema.is(PluginError);
const toPluginError = (error: RelayRequestError | PluginError) =>
  isPluginError(error) ? error : new PluginError({ message: error.message });
const uuid = SecureRandom.SecureRandom.pipe(Effect.flatMap((random) => random.uuidV4()));
const isoFromSeconds = (seconds: number) =>
  DateTime.formatIso(DateTime.makeUnsafe(seconds * 1_000));

/** Single-use guards for relay proofs, which live at most five minutes. */
export function makeReplayGuard() {
  const seen = new Map<string, number>();
  return (keys: ReadonlyArray<string>, nowMs: number) => {
    for (const [key, expiresAt] of seen) if (expiresAt <= nowMs) seen.delete(key);
    if (keys.some((key) => seen.has(key))) return false;
    for (const key of keys) seen.set(key, nowMs + 10 * 60_000);
    return true;
  };
}

export const makeBridge = Effect.fn("bridge.make")(function* (onLinked: Effect.Effect<void>) {
  const ctx = yield* PluginContext;
  const services = yield* Effect.context<PluginServices>();
  const provided = <A, E>(effect: Effect.Effect<A, E, PluginServices>) =>
    effect.pipe(Effect.provideContext(services));
  const pluginScope = yield* Effect.scope;
  const state = yield* Ref.make<RuntimeState>({
    pendingSignIn: null,
    tunnel: "off",
    hostname: null,
    error: null,
  });
  const linkLock = yield* Semaphore.make(1);
  const consumeReplay = makeReplayGuard();
  let tunnelScope: Scope.Closeable | null = null;
  let signInFiber: Fiber.Fiber<void> | null = null;
  let lastRecoveryAt = Number.NEGATIVE_INFINITY;
  let recoveryCooldown = RECOVERY_COOLDOWN;

  const readJson = <A, I>(key: string, schema: Schema.Codec<A, I>) =>
    ctx.storage
      .get(key)
      .pipe(Effect.map(Option.flatMap(Schema.decodeUnknownOption(Schema.fromJsonString(schema)))));
  const writeJson = <A, I>(key: string, schema: Schema.Codec<A, I>, value: A) =>
    Schema.encodeEffect(Schema.fromJsonString(schema))(value).pipe(
      Effect.mapError(
        (cause) => new PluginError({ message: "Could not save T3 Connect state.", cause }),
      ),
      Effect.flatMap((json) => ctx.storage.set(key, json)),
    );

  const readConfig = readJson(KEYS.config, BridgeConfig).pipe(
    Effect.map(Option.getOrElse(() => DEFAULT_CONFIG)),
  );
  const readLink = readJson(KEYS.link, StoredLink).pipe(Effect.map(Option.getOrNull));

  const signingKey = Effect.gen(function* () {
    const existing = yield* readJson(KEYS.signingKey, KeyPair);
    if (Option.isSome(existing)) return existing.value;
    const created = yield* generateKeyPair;
    yield* writeJson(KEYS.signingKey, KeyPair, created);
    return created;
  });

  const setState = (update: Partial<RuntimeState>) =>
    Ref.update(state, (current) => ({ ...current, ...update })).pipe(Effect.andThen(publishStatus));

  const status = Effect.gen(function* () {
    const [config, token, link, runtime] = yield* Effect.all([
      readConfig,
      readJson(KEYS.token, StoredToken),
      readLink,
      Ref.get(state),
    ]);
    return {
      account: Option.isSome(token) ? token.value.identity : null,
      signedIn: Option.isSome(token),
      pendingSignIn: runtime.pendingSignIn,
      linked: link !== null,
      tunnel: runtime.tunnel,
      hostname: runtime.hostname,
      error: runtime.error,
      config,
    } satisfies BridgeStatus;
  });

  const publishStatus: Effect.Effect<void> = status.pipe(
    Effect.flatMap((current) =>
      ctx.reportStatus(
        current.error ??
          (current.linked
            ? current.tunnel === "connected" && current.hostname
              ? `Linked · ${current.hostname}`
              : current.tunnel === "off"
                ? "Linked"
                : `Linked · tunnel ${current.tunnel}`
            : current.signedIn
              ? "Signed in, not linked"
              : "Not signed in"),
      ),
    ),
    Effect.ignore,
  );

  const validToken = Effect.gen(function* () {
    const stored = yield* readJson(KEYS.token, StoredToken);
    if (Option.isNone(stored)) {
      return yield* new PluginError({ message: "Sign in to T3 Connect first." });
    }
    const config = yield* readConfig;
    const fresh = yield* refreshIfNeeded(config, stored.value);
    if (Option.isNone(fresh)) {
      yield* ctx.storage.remove(KEYS.token);
      return yield* new PluginError({ message: "The T3 Connect sign-in expired. Sign in again." });
    }
    if (fresh.value !== stored.value) yield* writeJson(KEYS.token, StoredToken, fresh.value);
    return fresh.value;
  });

  const stopTunnel = Effect.gen(function* () {
    const scope = tunnelScope;
    tunnelScope = null;
    if (scope !== null) yield* Scope.close(scope, Exit.void);
    yield* Ref.update(state, (current) => ({ ...current, tunnel: "off" as const, hostname: null }));
  });

  const readHostname = (metricsAddress: string) =>
    HttpClient.HttpClient.pipe(
      Effect.flatMap((client) => client.get(`http://${metricsAddress}/config`)),
      Effect.flatMap(HttpClientResponse.schemaBodyJson(ConnectorConfigBody)),
      Effect.map((body) => body.config.ingress?.find((rule) => rule.hostname)?.hostname ?? null),
      Effect.timeout("5 seconds"),
      Effect.orElseSucceed(() => null),
    );

  // Recovery replaces the relay-side tunnel by linking again; back off when it keeps failing.
  const relinkAfterRejection = Effect.gen(function* () {
    const now = yield* Clock.currentTimeMillis;
    const since = now - lastRecoveryAt;
    recoveryCooldown =
      since > Duration.toMillis(recoveryCooldown) + 10 * 60_000
        ? RECOVERY_COOLDOWN
        : Duration.min(Duration.times(recoveryCooldown, 2), RECOVERY_MAX_COOLDOWN);
    const wait = Duration.toMillis(recoveryCooldown) - since;
    if (wait > 0) yield* Effect.sleep(Duration.millis(wait));
    lastRecoveryAt = yield* Clock.currentTimeMillis;
    yield* Effect.logWarning("T3 Connect rejected the tunnel; linking again");
    yield* link.pipe(Effect.catch((error) => setState({ error: error.message })));
  });

  let rejections = 0;
  const onConnectorLine = (line: string) => {
    switch (classifyConnectorLine(line)) {
      case "connected":
        rejections = 0;
        return Ref.get(state).pipe(
          Effect.flatMap((current) =>
            current.tunnel === "connected"
              ? Effect.void
              : setState({ tunnel: "connected", error: null }),
          ),
        );
      case "metrics": {
        const address = METRICS_LINE.exec(line)?.[1];
        if (address === undefined) return Effect.void;
        // The ingress hostname arrives only after the first connection registers.
        return Effect.sleep("5 seconds").pipe(
          Effect.andThen(readHostname(address)),
          Effect.flatMap((hostname) => (hostname ? setState({ hostname }) : Effect.void)),
          Effect.forkIn(pluginScope),
          Effect.asVoid,
        );
      }
      case "rejected":
        rejections += 1;
        return rejections === REJECTIONS_BEFORE_RELINK
          ? relinkAfterRejection.pipe(Effect.forkIn(pluginScope), Effect.asVoid)
          : Effect.void;
      case "other":
        return Effect.logDebug("cloudflared", { line });
    }
  };

  const superviseTunnel = Effect.fn("bridge.superviseTunnel")(
    function* (runtime: ManagedEndpointRuntimeConfig) {
      const executable = yield* ensureCloudflared(ctx.dataDir);
      let backoffMs = 1_000;
      while (true) {
        yield* setState({ tunnel: "starting" });
        const startedAt = yield* Clock.currentTimeMillis;
        rejections = 0;
        const exit = yield* Effect.scoped(
          spawnConnector({
            executable,
            connectorToken: runtime.connectorToken,
            onLine: (line) => provided(onConnectorLine(line)),
          }).pipe(Effect.flatMap((child) => child.exitCode)),
        ).pipe(Effect.exit);
        const uptime = (yield* Clock.currentTimeMillis) - startedAt;
        backoffMs = uptime > 30_000 ? 1_000 : Math.min(backoffMs * 2, 60_000);
        yield* Effect.logWarning("cloudflared exited; restarting", { exit, backoffMs });
        yield* setState({ tunnel: "failed" });
        yield* Effect.sleep(Duration.millis(backoffMs));
      }
    },
    Effect.catch((error) => setState({ tunnel: "failed", error: error.message })),
  );

  const startTunnel = Effect.fn("bridge.startTunnel")(function* (
    runtime: ManagedEndpointRuntimeConfig | null,
  ) {
    yield* stopTunnel;
    if (runtime === null || runtime.providerKind !== "cloudflare_tunnel") return;
    const scope = yield* Scope.fork(pluginScope);
    tunnelScope = scope;
    yield* superviseTunnel(runtime).pipe(Effect.forkIn(scope));
  });

  const linkUnlocked = Effect.gen(function* () {
    const config = yield* readConfig;
    const token = yield* validToken;
    const relayUrl = normalizeRelayUrl(config.relayUrl);
    if (relayUrl === null) {
      return yield* new PluginError({ message: "The relay URL must be an HTTPS origin." });
    }
    const local = parseLocalOrigin(yield* ctx.environment.localOrigin);
    const capabilities = {
      notificationsEnabled: true,
      liveActivitiesEnabled: true,
      managedTunnelsEnabled: true,
    };
    const challenge = yield* relayRequest({
      method: "POST",
      url: `${relayUrl}/v1/client/environment-link-challenges`,
      bearer: token.accessToken,
      body: capabilities,
      schema: LinkChallengeResponse,
    });
    const [environmentId, descriptor, keys] = yield* Effect.all([
      ctx.environment.environmentId,
      ctx.environment.descriptor,
      signingKey,
    ]);
    const nowSeconds = Math.floor((yield* Clock.currentTimeMillis) / 1_000);
    // Borrow the relay's clock; the relay still verifies and consumes the challenge.
    const issuedAt = (yield* unverifiedIssuedAt(challenge.challenge)) ?? nowSeconds;
    const proof = yield* signJwt({
      privateKeyPem: keys.privateKey,
      typ: RELAY_LINK_PROOF_TYP,
      payload: {
        iss: `t3-env:${environmentId}`,
        aud: normalizeIssuer(relayUrl),
        sub: environmentId,
        jti: yield* uuid,
        iat: issuedAt,
        exp: issuedAt + 5 * 60,
        challenge: challenge.challenge,
        descriptor,
        environmentId,
        environmentPublicKey: keys.publicKey.trim(),
        endpoint: {
          httpBaseUrl: local.httpBaseUrl,
          wsBaseUrl: local.wsBaseUrl,
          providerKind: "cloudflare_tunnel",
        },
        origin: local.origin,
        scopes: ["agent_activity_notifications", "managed_tunnels"],
      },
    });
    const linked = yield* relayRequest({
      method: "POST",
      url: `${relayUrl}/v1/client/environment-links`,
      bearer: token.accessToken,
      body: { proof, ...capabilities },
      schema: LinkResponse,
      timeout: "2 minutes",
    });
    if (!(yield* isValidPublicKey(linked.cloudMintPublicKey))) {
      return yield* new PluginError({ message: "T3 Connect returned an invalid signing key." });
    }
    yield* writeJson(KEYS.link, StoredLink, {
      relayUrl,
      relayIssuer: linked.relayIssuer,
      cloudUserId: linked.cloudUserId,
      environmentCredential: linked.environmentCredential,
      cloudMintPublicKey: linked.cloudMintPublicKey,
      endpointRuntime: linked.endpointRuntime,
    });
    yield* ctx.storage.set(KEYS.wantLinked, "true");
    yield* setState({ error: null });
    yield* startTunnel(linked.endpointRuntime);
    yield* onLinked;
  }).pipe(Effect.mapError(toPluginError));

  const link: Effect.Effect<void, PluginError, PluginServices> = linkLock.withPermits(1)(
    linkUnlocked.pipe(Effect.tapError((error) => setState({ error: error.message }))),
  );

  /** Cloudflare bills provisioned tunnels, so a stopped bridge releases its tunnel. */
  const releaseTunnel = Effect.gen(function* () {
    const storedLink = yield* readLink;
    yield* stopTunnel;
    if (storedLink?.endpointRuntime == null) return;
    const token = yield* validToken;
    const environmentId = yield* ctx.environment.environmentId;
    yield* relayRequest({
      method: "DELETE",
      url: `${storedLink.relayUrl}/v1/client/environment-links/${encodeURIComponent(environmentId)}/tunnel`,
      bearer: token.accessToken,
      schema: OkResponse,
      timeout: "5 seconds",
    });
    yield* writeJson(KEYS.link, StoredLink, { ...storedLink, endpointRuntime: null });
  }).pipe(
    Effect.catch((error) =>
      Effect.logWarning("Could not release the T3 Connect tunnel", { error }),
    ),
  );

  const unlinkUnlocked = Effect.gen(function* () {
    const storedLink = yield* readLink;
    yield* stopTunnel;
    yield* ctx.storage.remove(KEYS.wantLinked);
    if (storedLink !== null) {
      const environmentId = yield* ctx.environment.environmentId;
      yield* validToken.pipe(
        Effect.flatMap((token) =>
          relayRequest({
            method: "DELETE",
            url: `${storedLink.relayUrl}/v1/client/environment-links/${encodeURIComponent(environmentId)}`,
            bearer: token.accessToken,
            schema: OkResponse,
          }),
        ),
        Effect.catch((error) =>
          Effect.logWarning("T3 Connect did not confirm the unlink", { error }),
        ),
      );
    }
    yield* ctx.storage.remove(KEYS.link);
    yield* ctx.deviceAccess.revokeAll;
    yield* setState({ error: null });
  });
  const unlink = linkLock.withPermits(1)(unlinkUnlocked);

  const cancelSignIn = Effect.gen(function* () {
    const fiber = signInFiber;
    signInFiber = null;
    if (fiber !== null) yield* Fiber.interrupt(fiber);
    yield* Ref.update(state, (current) => ({ ...current, pendingSignIn: null }));
  });

  const signIn = Effect.gen(function* () {
    if ((yield* Ref.get(state)).pendingSignIn !== null) return;
    const config = yield* readConfig;
    const authorization: DeviceAuthorization = yield* startDeviceAuthorization(config);
    yield* setState({
      pendingSignIn: {
        verificationUrl: authorization.verificationUrl,
        userCode: authorization.userCode,
      },
      error: null,
    });
    signInFiber = yield* pollDeviceToken(config, authorization).pipe(
      Effect.flatMap((token) => writeJson(KEYS.token, StoredToken, token)),
      Effect.andThen(setState({ pendingSignIn: null })),
      // Signing in is only ever for linking, so finish the job.
      Effect.andThen(link),
      Effect.catch((error) => setState({ pendingSignIn: null, error: error.message })),
      Effect.ensuring(Effect.sync(() => (signInFiber = null))),
      Effect.forkIn(pluginScope),
    );
  });

  const signOut = Effect.gen(function* () {
    yield* cancelSignIn;
    yield* unlink;
    yield* ctx.storage.remove(KEYS.token);
    yield* setState({ error: null });
  });

  const setConfig = Effect.fn("bridge.setConfig")(function* (patch: BridgeConfigPatch) {
    const current = yield* readConfig;
    const next = { ...current, ...patch };
    if (normalizeRelayUrl(next.relayUrl) === null) {
      return yield* new PluginError({ message: "The relay URL must be an HTTPS origin." });
    }
    yield* writeJson(KEYS.config, BridgeConfig, next);
  });

  const nowSeconds = Clock.currentTimeMillis.pipe(Effect.map((ms) => Math.floor(ms / 1_000)));

  const reject = (status: number, message: string) =>
    Effect.succeed({ status, body: { _tag: "EnvironmentHttpError", message } });

  /** Verifies a relay-signed proof against the link's mint key and spends its jti and nonce. */
  const verifyRelayProof = Effect.fn("bridge.verifyRelayProof")(function* <
    A extends { jti: string; nonce: string; iat: number; exp: number },
  >(
    body: unknown,
    schema: Schema.Codec<A, unknown>,
    typ: string,
    accept: (claims: A, context: { environmentId: string; cloudUserId: string }) => boolean,
  ) {
    const request = decodeProofRequest(body);
    const storedLink = yield* readLink.pipe(Effect.orElseSucceed(() => null));
    if (Option.isNone(request) || storedLink === null) return null;
    const environmentId = yield* ctx.environment.environmentId;
    const claims = yield* verifyJwt(schema, {
      publicKeyPem: storedLink.cloudMintPublicKey,
      token: request.value.proof,
      typ,
      issuer: normalizeIssuer(storedLink.relayIssuer),
      audience: `t3-env:${environmentId}`,
    }).pipe(Effect.option);
    if (
      Option.isNone(claims) ||
      !hasBoundedLifetime({ ...claims.value, nowSeconds: yield* nowSeconds }) ||
      !accept(claims.value, { environmentId, cloudUserId: storedLink.cloudUserId })
    ) {
      return null;
    }
    const fresh = consumeReplay(
      [`${typ}:jti:${claims.value.jti}`, `${typ}:nonce:${claims.value.nonce}`],
      yield* Clock.currentTimeMillis,
    );
    return fresh ? { claims: claims.value, storedLink, environmentId } : ("replayed" as const);
  });

  const health = Effect.fn("bridge.health")(
    function* (body: unknown) {
      const verified = yield* verifyRelayProof(
        body,
        HealthProofPayload,
        RELAY_HEALTH_REQUEST_TYP,
        (claims, context) =>
          claims.environmentId === context.environmentId &&
          claims.sub === context.cloudUserId &&
          hasExactScope(claims.scope, "environment:status"),
      );
      if (verified === null) return yield* reject(401, "Invalid T3 Connect health request.");
      if (verified === "replayed") return yield* reject(409, "Health request already used.");
      const keys = yield* signingKey;
      const descriptor = yield* ctx.environment.descriptor;
      const issuedAt = yield* nowSeconds;
      const checkedAt = isoFromSeconds(issuedAt);
      const proof = yield* signJwt({
        privateKeyPem: keys.privateKey,
        typ: RELAY_HEALTH_RESPONSE_TYP,
        payload: {
          iss: `t3-env:${verified.environmentId}`,
          aud: normalizeIssuer(verified.storedLink.relayIssuer),
          sub: verified.environmentId,
          jti: yield* uuid,
          iat: issuedAt,
          exp: issuedAt + 5 * 60,
          environmentId: verified.environmentId,
          requestNonce: verified.claims.nonce,
          status: "online",
          descriptor,
          checkedAt,
        },
      });
      return {
        status: 200,
        body: {
          environmentId: verified.environmentId,
          status: "online",
          descriptor,
          checkedAt,
          proof,
        },
      };
    },
    Effect.catch((error) => reject(500, error.message)),
  );

  const mintCredential = Effect.fn("bridge.mintCredential")(
    function* (body: unknown) {
      const verified = yield* verifyRelayProof(
        body,
        MintCredentialProofPayload,
        RELAY_MINT_REQUEST_TYP,
        (claims, context) =>
          claims.environmentId === context.environmentId &&
          claims.sub === context.cloudUserId &&
          claims.cnf.jkt === claims.clientProofKeyThumbprint &&
          hasExactScope(claims.scope, "environment:connect"),
      );
      if (verified === null) return yield* reject(401, "Invalid T3 Connect mint request.");
      if (verified === "replayed") return yield* reject(409, "Mint request already used.");
      const issued = yield* ctx.deviceAccess.issueCredential({
        proofKeyThumbprint: verified.claims.clientProofKeyThumbprint,
        label: "T3 Connect",
      });
      const keys = yield* signingKey;
      const issuedAt = yield* nowSeconds;
      const proof = yield* signJwt({
        privateKeyPem: keys.privateKey,
        typ: RELAY_MINT_RESPONSE_TYP,
        payload: {
          iss: `t3-env:${verified.environmentId}`,
          aud: normalizeIssuer(verified.storedLink.relayIssuer),
          sub: verified.environmentId,
          jti: yield* uuid,
          iat: issuedAt,
          exp: Math.floor(issued.expiresAt.epochMilliseconds / 1_000),
          environmentId: verified.environmentId,
          clientProofKeyThumbprint: verified.claims.clientProofKeyThumbprint,
          requestNonce: verified.claims.nonce,
          credential: issued.credential,
        },
      });
      return {
        status: 200,
        body: {
          credential: issued.credential,
          expiresAt: DateTime.formatIso(issued.expiresAt),
          proof,
        },
      };
    },
    Effect.catch((error) => reject(500, error.message)),
  );

  /** Relinks a link that was active when the bridge last stopped; its tunnel was released. */
  const resume = Effect.gen(function* () {
    const wanted = yield* ctx.storage.get(KEYS.wantLinked);
    if (Option.isNone(wanted)) return;
    yield* link.pipe(
      Effect.retry({
        while: (error) => error.message.startsWith("Could not reach"),
        schedule: Schedule.exponential("5 seconds"),
        times: 8,
      }),
      Effect.ignore,
    );
  });

  yield* publishStatus;
  yield* Effect.addFinalizer(() => cancelSignIn.pipe(Effect.andThen(releaseTunnel), Effect.ignore));
  yield* resume.pipe(Effect.forkIn(pluginScope));

  const withStatus = <E>(effect: Effect.Effect<void, E, PluginServices>) =>
    provided(effect.pipe(Effect.andThen(publishStatus), Effect.andThen(status)));

  return {
    readLink,
    readConfig,
    signingKey: provided(signingKey),
    routes: {
      health: ((body) => provided(health(body))) satisfies PluginRouteHandler,
      mintCredential: ((body) => provided(mintCredential(body))) satisfies PluginRouteHandler,
    },
    actions: {
      status: () => provided(status),
      signIn: () => withStatus(signIn),
      signOut: () => withStatus(signOut),
      link: () => withStatus(link),
      unlink: () => withStatus(unlink),
      setConfig: (patch: BridgeConfigPatch) => withStatus(setConfig(patch)),
    },
  };
});
