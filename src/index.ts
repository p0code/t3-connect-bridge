import { definePlugin } from "@t3tools/plugin-api";
import * as Effect from "effect/Effect";
import * as Queue from "effect/Queue";

import { bridgeActions, T3_CONNECT_BRIDGE_ID } from "./actions.ts";
import { makeBridge } from "./bridge.ts";
import { runActivityPublisher } from "./push.ts";
import { HEALTH_ROUTE, MINT_ROUTE } from "./relayProtocol.ts";

export const t3ConnectBridge = definePlugin({
  manifest: {
    id: T3_CONNECT_BRIDGE_ID,
    name: "Unofficial T3 Connect bridge",
    description:
      "Links this environment to the official T3 Connect service, so T3 Code apps signed in to your T3 account can reach it and the store mobile app gets push notifications.",
    version: "0.1.0",
    unofficial: true,
    externalServices: ["relay.t3.codes", "clerk.t3.codes", "Cloudflare Tunnel"],
    capabilities: [
      "network:outbound",
      "process:spawn",
      "http:routes",
      "auth:issue-device-credentials",
      "orchestration:read-activity",
    ],
    httpRoutes: [HEALTH_ROUTE, MINT_ROUTE],
  },
  actions: bridgeActions,
  start: Effect.gen(function* () {
    const catchUpRequests = yield* Queue.sliding<void>(1);
    const bridge = yield* makeBridge(Queue.offer(catchUpRequests, undefined).pipe(Effect.asVoid));
    yield* runActivityPublisher({
      readLink: bridge.readLink,
      readConfig: bridge.readConfig,
      signingKey: bridge.signingKey,
      catchUpRequests,
    }).pipe(
      Effect.catchCause((cause) =>
        Effect.logError("T3 Connect activity publisher stopped", { cause }),
      ),
      Effect.forkScoped,
    );
    return {
      actions: bridge.actions,
      routes: {
        [HEALTH_ROUTE]: bridge.routes.health,
        [MINT_ROUTE]: bridge.routes.mintCredential,
      },
    };
  }),
});
