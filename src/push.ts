import type { ThreadId } from "@t3tools/contracts";
import { type ActivityState, PluginContext, type PluginError } from "@t3tools/plugin-api";
import * as Clock from "effect/Clock";
import * as SecureRandom from "effect/crypto/SecureRandom";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";

import type { BridgeConfig } from "./actions.ts";
import type { StoredLink } from "./bridge.ts";
import { type KeyPair, normalizeIssuer, signJwt } from "./jwt.ts";
import { relayRequest } from "./relay.ts";
import {
  AgentActivityState,
  PublishResponse,
  RELAY_ACTIVITY_PUBLISH_TYP,
} from "./relayProtocol.ts";

const CONFIRM_DELAY_MS = 5_000;
const RETRY_DELAYS_MS = [1_000, 4_000, 16_000, 60_000] as const;
const DETAIL_MAX_LENGTH = 160;
const CLEARED = "null";

const decodeState = Schema.decodeUnknownOption(AgentActivityState);

/** What changes an alert; a new `updatedAt` alone is not news. */
export function publishIdentity(state: ActivityState | null): string {
  if (state === null) return CLEARED;
  const { updatedAt: _updatedAt, ...rest } = state;
  return JSON.stringify(rest);
}

/** Clears and completions wait a beat: a run can end moments before its continuation starts. */
export function needsConfirmation(state: ActivityState | null): boolean {
  return state === null || state.phase === "completed";
}

export function toRelayState(state: ActivityState | null) {
  if (state === null) return Option.some(null);
  const detail = state.detail?.trim().slice(0, DETAIL_MAX_LENGTH).trim();
  const { detail: _detail, ...rest } = state;
  return decodeState(detail ? { ...rest, detail } : rest);
}

/**
 * Publishes agent activity to T3 Connect, which turns it into push notifications and Live
 * Activities on the store builds of T3 Code mobile.
 */
export const runActivityPublisher = Effect.fn("bridge.push.run")(function* (input: {
  readonly readLink: Effect.Effect<StoredLink | null, PluginError>;
  readonly readConfig: Effect.Effect<BridgeConfig, PluginError>;
  readonly signingKey: Effect.Effect<KeyPair, PluginError>;
  readonly catchUpRequests: Queue.Dequeue<void>;
}) {
  const ctx = yield* PluginContext;
  const queue = yield* Queue.unbounded<ThreadId>();
  const queued = new Set<ThreadId>();
  const published = new Map<ThreadId, string>();
  const confirmDeadlines = new Map<ThreadId, number>();
  const attempts = new Map<ThreadId, number>();
  let publishedCredential: string | null = null;

  const enqueue = (threadId: ThreadId) =>
    Effect.suspend(() => {
      if (queued.has(threadId)) return Effect.void;
      queued.add(threadId);
      return Queue.offer(queue, threadId).pipe(Effect.asVoid);
    });
  const enqueueLater = (threadId: ThreadId, delayMs: number) =>
    Effect.sleep(delayMs).pipe(Effect.andThen(enqueue(threadId)), Effect.forkScoped, Effect.asVoid);

  const publish = Effect.fn("bridge.push.publish")(function* (threadId: ThreadId) {
    const [config, link] = yield* Effect.all([input.readConfig, input.readLink]);
    if (!config.pushNotifications || link === null) {
      published.clear();
      publishedCredential = null;
      return;
    }
    if (publishedCredential !== link.environmentCredential) {
      published.clear();
      publishedCredential = link.environmentCredential;
    }
    const state = yield* ctx.agentActivity.read(threadId);
    const identity = publishIdentity(state);
    const previous = published.get(threadId);
    if (previous === identity) return;
    const hadLiveState = previous !== undefined && previous !== CLEARED;
    // Nothing to clear, and no alerts for work that finished before anyone was watching.
    if (
      !hadLiveState &&
      (state === null || state.phase === "completed" || state.phase === "failed")
    ) {
      return;
    }
    if (needsConfirmation(state)) {
      const now = yield* Clock.currentTimeMillis;
      const deadline = confirmDeadlines.get(threadId);
      if (deadline === undefined) {
        confirmDeadlines.set(threadId, now + CONFIRM_DELAY_MS);
        return yield* enqueueLater(threadId, CONFIRM_DELAY_MS);
      }
      if (now < deadline) return;
    }
    confirmDeadlines.delete(threadId);
    const relayState = toRelayState(state);
    if (Option.isNone(relayState)) {
      return yield* Effect.logDebug("Skipping agent activity the relay would reject", { threadId });
    }
    const environmentId = yield* ctx.environment.environmentId;
    const keys = yield* input.signingKey;
    const issuedAt = Math.floor((yield* Clock.currentTimeMillis) / 1_000);
    const proof = yield* signJwt({
      privateKeyPem: keys.privateKey,
      typ: RELAY_ACTIVITY_PUBLISH_TYP,
      payload: {
        iss: `t3-env:${environmentId}`,
        aud: normalizeIssuer(link.relayIssuer),
        sub: environmentId,
        jti: yield* SecureRandom.SecureRandom.pipe(Effect.flatMap((random) => random.uuidV4())),
        iat: issuedAt,
        exp: issuedAt + 5 * 60,
        environmentId,
        threadId,
        state: relayState.value,
      },
    });
    yield* relayRequest({
      method: "POST",
      url: `${link.relayUrl}/v1/environments/${encodeURIComponent(environmentId)}/threads/${encodeURIComponent(threadId)}/agent-activity`,
      bearer: link.environmentCredential,
      body: { state: relayState.value, proof },
      schema: PublishResponse,
    });
    published.set(threadId, identity);
  });

  const processThread = (threadId: ThreadId) =>
    Effect.sync(() => queued.delete(threadId)).pipe(
      Effect.andThen(publish(threadId)),
      Effect.tap(() => Effect.sync(() => attempts.delete(threadId))),
      Effect.catch((error) => {
        const attempt = attempts.get(threadId) ?? 0;
        attempts.set(threadId, attempt + 1);
        const delay = RETRY_DELAYS_MS[attempt] ?? 60_000;
        return Effect.logWarning("Could not publish agent activity to T3 Connect", {
          threadId,
          error: error.message,
        }).pipe(Effect.andThen(enqueueLater(threadId, delay)));
      }),
    );

  const catchUp = ctx.agentActivity.activeThreadIds.pipe(
    Effect.flatMap((ids) => Effect.forEach(ids, enqueue, { discard: true })),
    Effect.catch((error) => Effect.logWarning("Could not read active threads", { error })),
  );

  yield* Stream.runForEach(ctx.agentActivity.changes, enqueue).pipe(Effect.forkScoped);
  yield* catchUp;
  yield* Queue.take(input.catchUpRequests).pipe(
    Effect.andThen(catchUp),
    Effect.forever,
    Effect.forkScoped,
  );
  return yield* Queue.take(queue).pipe(Effect.flatMap(processThread), Effect.forever);
});
