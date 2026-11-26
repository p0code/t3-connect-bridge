import { EnvironmentId, ThreadId } from "@t3tools/contracts";
import type { ActivityState } from "@t3tools/plugin-api";
import { PluginContext, PluginError } from "@t3tools/plugin-api";
import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import * as NodeServices from "@effect/platform-node/NodeServices";
import { assert, describe, it } from "@effect/vitest";
import * as DateTime from "effect/DateTime";
import * as Effect from "effect/Effect";
import * as FetchHttpClient from "effect/http/FetchHttpClient";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";

import { makeBridge, makeReplayGuard } from "./bridge.ts";
import { classifyConnectorLine } from "./cloudflared.ts";
import { generateKeyPair, hasBoundedLifetime, signJwt, verifyJwt } from "./jwt.ts";
import { clerkFrontendApiUrl, identityFromIdToken } from "./oauth.ts";
import { needsConfirmation, publishIdentity, toRelayState } from "./push.ts";
import { describeRefusal, normalizeRelayUrl, parseLocalOrigin, relayRequest } from "./relay.ts";
import {
  LinkResponse,
  RELAY_MINT_REQUEST_TYP,
  RELAY_MINT_RESPONSE_TYP,
} from "./relayProtocol.ts";

const ENVIRONMENT_ID = EnvironmentId.make("env-1");
const RELAY_ISSUER = "https://relay.example";
const decodeMintBody = Schema.decodeUnknownEffect(
  Schema.Struct({ credential: Schema.String, proof: Schema.String }),
);
const ResponseClaims = Schema.Struct({ requestNonce: Schema.String });
const decodeStoredKeys = Schema.decodeUnknownEffect(
  Schema.fromJsonString(Schema.Struct({ publicKey: Schema.String })),
);

describe("public config", () => {
  it("derives Clerk's Frontend API from upstream's publishable key", () => {
    assert.strictEqual(
      clerkFrontendApiUrl("pk_live_Y2xlcmsudDMuY29kZXMk"),
      "https://clerk.t3.codes",
    );
    assert.isNull(clerkFrontendApiUrl("pk_live_not-base64!"));
  });

  it("accepts only bare HTTPS relay origins", () => {
    assert.strictEqual(normalizeRelayUrl("https://relay.t3.codes/"), "https://relay.t3.codes");
    assert.isNull(normalizeRelayUrl("http://relay.t3.codes"));
    assert.isNull(normalizeRelayUrl("https://relay.t3.codes/v1"));
  });

  it("signs the server's own loopback origin", () => {
    assert.deepStrictEqual(parseLocalOrigin("http://[::1]:3773").origin, {
      localHttpHost: "::1",
      localHttpPort: 3773,
    });
  });

  it("reads the account from an ID token", () => {
    const payload = Buffer.from(JSON.stringify({ email: "a@example.com" })).toString("base64url");
    assert.strictEqual(identityFromIdToken(`x.${payload}.y`), "a@example.com");
    assert.isNull(identityFromIdToken(undefined));
  });
});

describe("cloudflared output", () => {
  it("classifies registration, rejection and metrics lines", () => {
    assert.strictEqual(
      classifyConnectorLine(
        "2026-01-01 INF Registered tunnel connection connIndex=0 protocol=quic",
      ),
      "connected",
    );
    assert.strictEqual(
      classifyConnectorLine('ERR Register tunnel error from server side error="Unauthorized: bad"'),
      "rejected",
    );
    assert.strictEqual(
      classifyConnectorLine("INF Starting metrics server on 127.0.0.1:4567/metrics"),
      "metrics",
    );
  });
});

describe("proof checks", () => {
  it("rejects long-lived or future proofs", () => {
    assert.isTrue(hasBoundedLifetime({ iat: 100, exp: 160, nowSeconds: 100 }));
    assert.isFalse(hasBoundedLifetime({ iat: 100, exp: 1_000, nowSeconds: 100 }));
    assert.isFalse(hasBoundedLifetime({ iat: 500, exp: 560, nowSeconds: 100 }));
  });

  it("spends each guard key once", () => {
    const consume = makeReplayGuard();
    assert.isTrue(consume(["a", "b"], 0));
    assert.isFalse(consume(["b"], 1));
    assert.isTrue(consume(["b"], 11 * 60_000));
  });
});

describe("activity publishing", () => {
  const state: ActivityState = {
    environmentId: ENVIRONMENT_ID,
    threadId: ThreadId.make("thread-1"),
    projectTitle: "Project",
    threadTitle: "Thread",
    phase: "running",
    headline: "Working",
    modelTitle: "model",
    updatedAt: "2026-01-01T00:00:00.000Z",
    deepLink: "/threads/env-1/thread-1",
  };

  it("ignores timestamp-only changes and holds completions", () => {
    assert.strictEqual(
      publishIdentity(state),
      publishIdentity({ ...state, updatedAt: "2026-01-02T00:00:00.000Z" }),
    );
    assert.isTrue(needsConfirmation(null));
    assert.isTrue(needsConfirmation({ ...state, phase: "completed" }));
    assert.isFalse(needsConfirmation(state));
  });

  it("drops states the relay would reject", () => {
    assert.isTrue(Option.isSome(toRelayState(state)));
    assert.isTrue(Option.isNone(toRelayState({ ...state, threadTitle: "" })));
  });
});

const layerPlatform = Layer.mergeAll(NodeServices.layer, NodeCrypto.layer, FetchHttpClient.layer);
const layerWithHttp = (http: HttpClient.HttpClient) =>
  Layer.mergeAll(NodeServices.layer, NodeCrypto.layer, Layer.succeed(HttpClient.HttpClient, http));

const makeTestContext = (storage: Map<string, string>, issued: Array<string> = []) => {
  const notSupported = Effect.fail(
    new PluginError({ message: "data backup is not supported in this test" }),
  );
  return PluginContext.of({
    usage: { dailyTotals: () => Effect.succeed([]) },
    pluginId: "t3-connect-bridge",
    dataDir: "/nonexistent",
    routes: { secret: "test-route-secret" },
    storage: {
      get: (key) => Effect.succeed(Option.fromNullishOr(storage.get(key))),
      set: (key, value) => Effect.sync(() => void storage.set(key, value)),
      remove: (key) => Effect.sync(() => void storage.delete(key)),
    },
    reportStatus: () => Effect.void,
    environment: {
      environmentId: Effect.succeed(ENVIRONMENT_ID),
      descriptor: Effect.die("unused"),
      localOrigin: Effect.succeed("http://127.0.0.1:3773"),
    },
    deviceAccess: {
      issueCredential: ({ proofKeyThumbprint }) =>
        DateTime.now.pipe(
          Effect.map((now) => {
            issued.push(proofKeyThumbprint);
            return {
              credential: "pairing-credential",
              expiresAt: DateTime.add(now, { minutes: 2 }),
            };
          }),
        ),
      revokeAll: Effect.void,
    },
    agentActivity: {
      changes: Stream.empty,
      read: () => Effect.succeed(null),
      activeThreadIds: Effect.succeed([]),
    },
    dataBackup: {
      snapshot: notSupported,
      stageRestore: () => notSupported,
      pendingRestore: notSupported,
      cancelRestore: notSupported,
    },
  });
};

const mintProof = (input: {
  readonly privateKeyPem: string;
  readonly nonce: string;
  readonly scope?: ReadonlyArray<string>;
}) =>
  Effect.gen(function* () {
    const now = Math.floor((yield* DateTime.now).epochMilliseconds / 1_000);
    return yield* signJwt({
      privateKeyPem: input.privateKeyPem,
      typ: RELAY_MINT_REQUEST_TYP,
      payload: {
        iss: RELAY_ISSUER,
        aud: `t3-env:${ENVIRONMENT_ID}`,
        sub: "user_1",
        jti: `jti-${input.nonce}`,
        iat: now,
        exp: now + 60,
        environmentId: ENVIRONMENT_ID,
        clientProofKeyThumbprint: "thumb",
        cnf: { jkt: "thumb" },
        nonce: input.nonce,
        scope: input.scope ?? ["environment:connect"],
      },
    });
  });

describe("relay requests", () => {
  it.live("mints a device credential only for a fresh, relay-signed proof", () =>
    Effect.gen(function* () {
      const relayKeys = yield* generateKeyPair;
      const storage = new Map<string, string>([
        [
          "link",
          JSON.stringify({
            relayUrl: RELAY_ISSUER,
            relayIssuer: RELAY_ISSUER,
            cloudUserId: "user_1",
            environmentCredential: "credential",
            cloudMintPublicKey: relayKeys.publicKey,
            endpointRuntime: null,
          }),
        ],
      ]);
      const issued: Array<string> = [];
      const context = makeTestContext(storage, issued);

      const bridge = yield* makeBridge(Effect.void).pipe(
        Effect.provideService(PluginContext, context),
      );
      const proof = yield* mintProof({ privateKeyPem: relayKeys.privateKey, nonce: "n1" });
      const minted = yield* bridge.routes.mintCredential({ proof });
      assert.strictEqual(minted.status, 200);
      assert.deepStrictEqual(issued, ["thumb"]);

      const body = yield* decodeMintBody(minted.body);
      assert.strictEqual(body.credential, "pairing-credential");
      const environmentKeys = yield* decodeStoredKeys(storage.get("signing-key"));
      const response = yield* verifyJwt(ResponseClaims, {
        publicKeyPem: environmentKeys.publicKey,
        token: body.proof,
        typ: RELAY_MINT_RESPONSE_TYP,
        issuer: `t3-env:${ENVIRONMENT_ID}`,
        audience: RELAY_ISSUER,
      });
      assert.strictEqual(response.requestNonce, "n1");

      const replayed = yield* bridge.routes.mintCredential({ proof });
      assert.strictEqual(replayed.status, 409);
      const wrongScope = yield* mintProof({
        privateKeyPem: relayKeys.privateKey,
        nonce: "n2",
        scope: ["environment:status"],
      }).pipe(Effect.flatMap((token) => bridge.routes.mintCredential({ proof: token })));
      assert.strictEqual(wrongScope.status, 401);
      const forged = yield* generateKeyPair.pipe(
        Effect.flatMap((keys) => mintProof({ privateKeyPem: keys.privateKey, nonce: "n3" })),
        Effect.flatMap((token) => bridge.routes.mintCredential({ proof: token })),
      );
      assert.strictEqual(forged.status, 401);
      assert.deepStrictEqual(issued, ["thumb"]);
    }).pipe(Effect.scoped, Effect.provide(layerPlatform)),
  );
});

describe("link refusals", () => {
  const refusal = (reason: string, traceId?: string) =>
    JSON.stringify({
      _tag: "RelayEnvironmentLinkProofInvalidError",
      reason,
      ...(traceId === undefined ? {} : { traceId }),
    });

  it("gives every reason its own sentence for the panel", () => {
    const reasons = [
      "environment_key_mismatch",
      "invalid_signature_or_scope",
      "descriptor_mismatch",
      "replayed_nonce",
      "challenge_invalid",
      "origin_not_allowed",
      "endpoint_not_secure",
    ];
    const messages = reasons.map((reason) =>
      describeRefusal({ _tag: "RelayEnvironmentLinkProofInvalidError", reason }),
    );
    assert.strictEqual(new Set(messages).size, reasons.length);
    const mismatch = describeRefusal({
      _tag: "RelayEnvironmentLinkProofInvalidError",
      reason: "environment_key_mismatch",
      traceId: "trace-1",
    });
    assert.include(mismatch, "already linked with a different key");
    assert.include(mismatch, "Unlink it here and link again, or restore the old key");
    assert.include(mismatch, "environment_key_mismatch");
    assert.include(mismatch, "trace-1");
    assert.notInclude(messages[5], "different key");
    const unknown = describeRefusal({ _tag: "RelayBadRequestError", reason: "new_reason" });
    assert.include(unknown, "RelayBadRequestError");
    assert.include(unknown, "new_reason");
    assert.strictEqual(
      describeRefusal({ _tag: "RelayBadRequestError" }),
      "T3 Connect refused the request (RelayBadRequestError).",
    );
  });

  it.live("carries the relay's reason into the failure message", () => {
    const http = HttpClient.make((request) =>
      Effect.succeed(
        HttpClientResponse.fromWeb(
          request,
          new Response(refusal("environment_key_mismatch", "trace-1"), {
            status: 403,
            headers: { "content-type": "application/json" },
          }),
        ),
      ),
    );
    return Effect.gen(function* () {
      const error = yield* relayRequest({
        method: "POST",
        url: `${RELAY_ISSUER}/v1/client/environment-links`,
        bearer: "token",
        body: { proof: "x" },
        schema: LinkResponse,
      }).pipe(Effect.flip);
      assert.include(error.message, "environment_key_mismatch");
      assert.include(error.message, "already linked with a different key");
      assert.include(error.message, "trace-1");
    }).pipe(Effect.provide(layerWithHttp(http)));
  });
});

describe("unlinking", () => {
  it.live("asks the relay even when this home has no stored link", () => {
    const requests: Array<{ readonly method: string; readonly url: string }> = [];
    const http = HttpClient.make((request) =>
      Effect.sync(() => {
        requests.push({ method: request.method, url: request.url });
        return HttpClientResponse.fromWeb(request, Response.json({ ok: true }));
      }),
    );
    return Effect.gen(function* () {
      const now = yield* DateTime.now;
      const storage = new Map<string, string>([
        ["config", JSON.stringify({ relayUrl: "https://relay.example" })],
        [
          "token",
          JSON.stringify({
            accessToken: "access",
            refreshToken: "refresh",
            expiresAtEpochMs: now.epochMilliseconds + 60 * 60_000,
            identity: "me@example.com",
          }),
        ],
      ]);
      const bridge = yield* makeBridge(Effect.void).pipe(
        Effect.provideService(PluginContext, makeTestContext(storage)),
      );
      const status = yield* bridge.actions.unlink();
      assert.isFalse(status.linked);
      assert.isNull(status.error);
      assert.deepEqual(requests, [
        { method: "DELETE", url: "https://relay.example/v1/client/environment-links/env-1" },
      ]);
      assert.isFalse(storage.has("link"));
      assert.isFalse(storage.has("want-linked"));
    }).pipe(Effect.scoped, Effect.provide(layerWithHttp(http)));
  });
});
