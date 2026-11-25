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

const describeFailure = Effect.fn("bridge.relay.describeFailure")(function* (
  response: HttpClientResponse.HttpClientResponse,
) {
  const body = yield* HttpClientResponse.schemaBodyJson(RelayErrorBody)(response).pipe(
    Effect.option,
  );
  const detail = Option.match(body, {
    onNone: () => `HTTP ${response.status}`,
    onSome: (error) => `${error._tag}${error.traceId ? `, trace ${error.traceId}` : ""}`,
  });
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
      : `T3 Connect refused the request (${detail}).`,
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
