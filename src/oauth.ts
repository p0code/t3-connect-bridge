import { PluginError } from "@t3tools/plugin-api";
import * as Clock from "effect/Clock";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Base64Url from "effect/encoding/Base64Url";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as HttpClientResponse from "effect/http/HttpClientResponse";

import type { BridgeConfig } from "./actions.ts";

const isPluginError = Schema.is(PluginError);

const SCOPES = "openid profile email offline_access";
const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const REQUEST_TIMEOUT = Duration.seconds(10);
const REFRESH_EARLY_MS = 5 * 60_000;

export const StoredToken = Schema.Struct({
  accessToken: Schema.String,
  refreshToken: Schema.String,
  expiresAtEpochMs: Schema.Number,
  identity: Schema.NullOr(Schema.String),
});
export type StoredToken = typeof StoredToken.Type;

const TokenResponse = Schema.Struct({
  access_token: Schema.String,
  refresh_token: Schema.optional(Schema.String),
  id_token: Schema.optional(Schema.String),
  expires_in: Schema.Number,
});

const ErrorResponse = Schema.Struct({ error: Schema.String });

const DeviceAuthorizationResponse = Schema.Struct({
  device_code: Schema.String,
  user_code: Schema.String,
  verification_uri: Schema.String,
  verification_uri_complete: Schema.optional(Schema.String),
  expires_in: Schema.Number,
  interval: Schema.optional(Schema.Number),
});

/** Clerk encodes its Frontend API host in the publishable key: `pk_live_<base64(host$)>`. */
export function clerkFrontendApiUrl(publishableKey: string): string | null {
  const encoded = publishableKey.trim().split("_").slice(2).join("_");
  try {
    const host = globalThis.atob(encoded).replace(/\$$/u, "");
    if (host.length === 0 || host.includes("/")) return null;
    return new URL(`https://${host}`).origin;
  } catch {
    return null;
  }
}

const endpoints = (config: BridgeConfig) => {
  const base = clerkFrontendApiUrl(config.clerkPublishableKey);
  return base === null
    ? Effect.fail(new PluginError({ message: "The Clerk publishable key is not valid." }))
    : Effect.succeed({
        token: `${base}/oauth/token`,
        deviceAuthorization: `${base}/oauth/device_authorization`,
      });
};

export function identityFromIdToken(idToken: string | undefined): string | null {
  const payload = idToken?.split(".")[1];
  if (!payload) return null;
  const decoded = Base64Url.decodeString(payload);
  if (decoded._tag !== "Success") return null;
  try {
    const claims: unknown = JSON.parse(decoded.success);
    if (typeof claims !== "object" || claims === null) return null;
    for (const key of ["email", "preferred_username", "sub"] as const) {
      const value: unknown = Reflect.get(claims, key);
      if (typeof value === "string" && value.length > 0) return value;
    }
  } catch {
    return null;
  }
  return null;
}

const toStoredToken = (body: typeof TokenResponse.Type, previous?: StoredToken) =>
  Clock.currentTimeMillis.pipe(
    Effect.map((now): StoredToken => ({
      accessToken: body.access_token,
      refreshToken: body.refresh_token ?? previous?.refreshToken ?? "",
      expiresAtEpochMs: now + body.expires_in * 1_000,
      identity: identityFromIdToken(body.id_token) ?? previous?.identity ?? null,
    })),
  );

const postForm = (url: string, params: Record<string, string>) =>
  HttpClient.HttpClient.pipe(
    Effect.flatMap((client) =>
      client.execute(HttpClientRequest.post(url).pipe(HttpClientRequest.bodyUrlParams(params))),
    ),
    Effect.timeout(REQUEST_TIMEOUT),
  );

export interface DeviceAuthorization {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUrl: string;
  readonly expiresIn: Duration.Duration;
  readonly interval: Duration.Duration;
}

/** RFC 8628 device authorization: works when the browser is on another machine. */
export const startDeviceAuthorization = Effect.fn("bridge.oauth.startDevice")(
  function* (config: BridgeConfig) {
    const urls = yield* endpoints(config);
    const response = yield* postForm(urls.deviceAuthorization, {
      client_id: config.cliOAuthClientId,
      scope: SCOPES,
    }).pipe(
      Effect.flatMap(HttpClientResponse.filterStatusOk),
      Effect.flatMap(HttpClientResponse.schemaBodyJson(DeviceAuthorizationResponse)),
    );
    return {
      deviceCode: response.device_code,
      userCode: response.user_code,
      verificationUrl: response.verification_uri_complete ?? response.verification_uri,
      expiresIn: Duration.seconds(response.expires_in),
      interval: Duration.seconds(response.interval ?? 5),
    } satisfies DeviceAuthorization;
  },
  Effect.mapError((cause) =>
    isPluginError(cause)
      ? cause
      : new PluginError({ message: "Could not reach T3 Connect sign-in.", cause }),
  ),
);

export const pollDeviceToken = Effect.fn("bridge.oauth.pollDevice")(
  function* (config: BridgeConfig, authorization: DeviceAuthorization) {
    const urls = yield* endpoints(config);
    let interval = authorization.interval;
    while (true) {
      yield* Effect.sleep(interval);
      const response = yield* postForm(urls.token, {
        grant_type: DEVICE_CODE_GRANT,
        device_code: authorization.deviceCode,
        client_id: config.cliOAuthClientId,
      }).pipe(Effect.option);
      if (Option.isNone(response) || response.value.status >= 500) {
        interval = Duration.sum(interval, Duration.seconds(5));
        continue;
      }
      if (response.value.status < 300) {
        const body = yield* HttpClientResponse.schemaBodyJson(TokenResponse)(response.value);
        return yield* toStoredToken(body);
      }
      const failure = yield* HttpClientResponse.schemaBodyJson(ErrorResponse)(response.value);
      if (failure.error === "authorization_pending") continue;
      if (failure.error === "slow_down") {
        interval = Duration.sum(interval, Duration.seconds(5));
        continue;
      }
      return yield* new PluginError({
        message:
          failure.error === "access_denied"
            ? "Sign-in was denied."
            : failure.error === "expired_token"
              ? "The sign-in code expired."
              : `Sign-in failed (${failure.error}).`,
      });
    }
  },
  (effect, _config, authorization) =>
    effect.pipe(
      Effect.timeoutOrElse({
        duration: authorization.expiresIn,
        orElse: () => Effect.fail(new PluginError({ message: "The sign-in code expired." })),
      }),
    ),
  Effect.mapError((cause) =>
    isPluginError(cause)
      ? cause
      : new PluginError({ message: "Could not finish T3 Connect sign-in.", cause }),
  ),
);

/** A fresh access token, refreshing when it is near expiry. `null` means sign in again. */
export const refreshIfNeeded = Effect.fn("bridge.oauth.refresh")(function* (
  config: BridgeConfig,
  token: StoredToken,
) {
  const now = yield* Clock.currentTimeMillis;
  if (token.expiresAtEpochMs - REFRESH_EARLY_MS > now) return Option.some(token);
  const urls = yield* endpoints(config);
  const response = yield* postForm(urls.token, {
    grant_type: "refresh_token",
    refresh_token: token.refreshToken,
    client_id: config.cliOAuthClientId,
  }).pipe(
    Effect.mapError(
      (cause) => new PluginError({ message: "Could not reach T3 Connect sign-in.", cause }),
    ),
  );
  if (response.status >= 400 && response.status < 500 && response.status !== 429) {
    return Option.none<StoredToken>();
  }
  const body = yield* HttpClientResponse.filterStatusOk(response).pipe(
    Effect.flatMap(HttpClientResponse.schemaBodyJson(TokenResponse)),
    Effect.mapError(
      (cause) => new PluginError({ message: "Could not refresh the T3 Connect sign-in.", cause }),
    ),
  );
  return Option.some(yield* toStoredToken(body, token));
});
