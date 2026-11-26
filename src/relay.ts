import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientRequest from "effect/http/HttpClientRequest";
import * as HttpClientResponse from "effect/http/HttpClientResponse";

import { RelayErrorBody } from "./relayProtocol.ts";

/** `unavailable` is the only failure worth retrying; the rest need someone to act. */
export class RelayRequestError extends Schema.TaggedError<RelayRequestError>()(
  "RelayRequestError",
  {
    rejection: Schema.Literals(["unauthorized", "rejected", "unavailable"]),
    message: Schema.String,
  },
) {}

const isRelayRequestError = Schema.is(RelayRequestError);

export function normalizeRelayUrl(value: string): string | null {
  try {
    const url = new URL(value.trim());
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== "" ||
      url.search !== "" ||
      url.hash !== "" ||
      !/^\/*$/u.test(url.pathname)
    ) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

/** Where the tunnel must deliver: this server's own loopback origin. */
export function parseLocalOrigin(localOrigin: string) {
  const url = new URL(localOrigin);
  const ws = new URL(url.origin);
  ws.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return {
    httpBaseUrl: url.origin,
    wsBaseUrl: ws.origin,
    origin: {
      localHttpHost: url.hostname.replace(/^\[(.*)\]$/u, "$1"),
      localHttpPort: Number(url.port || (url.protocol === "https:" ? 443 : 80)),
    },
  };
}

/**
 * The relay's `reason` is the only actionable part of a refusal, so each one gets its own
 * sentence. Unknown reasons still show the tag and reason verbatim.
 */
const REFUSAL_TEXT: Readonly<Record<string, string>> = {
  environment_key_mismatch:
    "This environment is already linked with a different key — Unlink it here and link again, or restore the old key",
  invalid_signature_or_scope:
    "T3 Connect rejected this machine's proof signature or scopes — Sign in again, then Link",
  descriptor_mismatch: "T3 Connect rejected this machine's descriptor — update p0code, then Link",
  replayed_nonce: "T3 Connect has seen this proof before — Link again",
  challenge_invalid: "The link challenge expired or was already used — Link again",
  origin_not_allowed: "T3 Connect does not allow this machine's origin",
  endpoint_not_secure: "The tunnel endpoint must be HTTPS",
};

/** What the panel shows for a relay refusal: the reason first, the wire tags after it. */
export function describeRefusal(error: {
  readonly _tag: string;
  readonly reason?: string | undefined;
  readonly traceId?: string | undefined;
}): string {
  const code =
    `${error._tag}${error.reason === undefined ? "" : `: ${error.reason}`}` +
    `${error.traceId === undefined ? "" : `, trace ${error.traceId}`}`;
  const advice = error.reason === undefined ? undefined : REFUSAL_TEXT[error.reason];
  return advice === undefined
    ? `T3 Connect refused the request (${code}).`
    : `${advice} (${code}).`;
}

const describeFailure = Effect.fn("bridge.relay.describeFailure")(function* (
  response: HttpClientResponse.HttpClientResponse,
) {
  const body = yield* HttpClientResponse.schemaBodyJson(RelayErrorBody)(response).pipe(
    Effect.option,
  );
  const limitExceeded =
    Option.isSome(body) && body.value._tag === "RelayEnvironmentLinkLimitExceededError";
  // An expired proof is clock skew, which a retry can outlast.
  const expired = Option.isSome(body) && body.value._tag.includes("Expired");
  return new RelayRequestError({
    rejection:
      response.status === 401 && !expired
        ? "unauthorized"
        : response.status >= 400 &&
            response.status < 500 &&
            response.status !== 408 &&
            response.status !== 429 &&
            !expired
          ? "rejected"
          : "unavailable",
    message: limitExceeded
      ? 'Your T3 Connect account has reached its linked-environment limit. Unlink an unused machine in T3 Code (or migrate with "Keep environment ID" enabled) and try again.'
      : Option.isSome(body)
        ? describeRefusal(body.value)
        : `T3 Connect refused the request (HTTP ${response.status}).`,
  });
});

export const relayRequest = Effect.fn("bridge.relay.request")(
  function* <A, I>(input: {
    readonly method: "POST" | "DELETE";
    readonly url: string;
    readonly bearer: string;
    readonly body?: unknown;
    readonly schema: Schema.Codec<A, I>;
    readonly timeout?: Duration.Input;
  }) {
    const client = yield* HttpClient.HttpClient;
    const base = (input.method === "POST" ? HttpClientRequest.post : HttpClientRequest.delete)(
      input.url,
    ).pipe(HttpClientRequest.bearerToken(input.bearer));
    const request =
      input.body === undefined ? base : yield* HttpClientRequest.bodyJson(base, input.body);
    const response = yield* client.execute(request);
    if (response.status < 200 || response.status >= 300) {
      return yield* yield* describeFailure(response);
    }
    return yield* HttpClientResponse.schemaBodyJson(input.schema)(response);
  },
  (effect, input) => effect.pipe(Effect.timeout(input.timeout ?? "10 seconds")),
  Effect.mapError((cause) =>
    isRelayRequestError(cause)
      ? cause
      : new RelayRequestError({
          rejection: "unavailable",
          message: "Could not reach T3 Connect. Check this machine's network connection.",
        }),
  ),
);
