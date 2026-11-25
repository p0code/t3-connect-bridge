// @effect-diagnostics nodeBuiltinImport:off globalFetchInEffect:off -- Exercise the ingress with real HTTP requests and a raw HTTP fixture.
import * as NodeHttp from "node:http";
import { assert, it } from "@effect/vitest";
import * as Effect from "effect/Effect";

import { makeRouteIngress, routeUrl } from "./routeIngress.ts";
import { HEALTH_ROUTE, MINT_ROUTE } from "./relayProtocol.ts";

it("adds the secret only to the relay callbacks and never changes the destination", () => {
  for (const path of [HEALTH_ROUTE, MINT_ROUTE]) {
    const url = routeUrl("http://127.0.0.1:3773", `${path}?extra=1`, "secret+/=");
    assert.strictEqual(url.searchParams.get("p0_route"), "secret+/=");
    assert.strictEqual(url.searchParams.get("extra"), "1");
  }
  assert.isNull(
    routeUrl("http://127.0.0.1:3773", "/api/other", "secret").searchParams.get("p0_route"),
  );
  assert.strictEqual(
    routeUrl("http://127.0.0.1:3773", "//evil.example/path", "secret").origin,
    "http://127.0.0.1:3773",
  );
});

it.live("forwards callback bodies through the registered loopback ingress", () =>
  Effect.gen(function* () {
    const received: Array<{ url: string | undefined; body: string }> = [];
    const target = yield* Effect.acquireRelease(
      Effect.promise(
        () =>
          new Promise<NodeHttp.Server>((resolve) => {
            const server = NodeHttp.createServer((request, response) => {
              let body = "";
              request.setEncoding("utf8");
              request.on("data", (chunk: string) => {
                body += chunk;
              });
              request.on("end", () => {
                received.push({ url: request.url, body });
                response.end("ok");
              });
            });
            server.on("upgrade", (_request, socket) => {
              socket.write(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
              );
              socket.on("data", (chunk: Buffer) => socket.write(chunk));
            });
            server.listen(0, "127.0.0.1", () => resolve(server));
          }),
      ),
      (server) =>
        Effect.sync(() => {
          server.closeAllConnections();
          server.close();
        }),
    );
    const address = target.address();
    assert.isNotNull(address);
    if (address === null || typeof address === "string") return;
    const ingress = yield* makeRouteIngress(`http://127.0.0.1:${address.port}`, "test-secret");
    for (const path of [HEALTH_ROUTE, MINT_ROUTE, "/api/other"]) {
      const response = yield* Effect.promise(() =>
        fetch(`${ingress}${path}`, { method: "POST", body: '{"proof":"signed"}' }),
      );
      assert.strictEqual(yield* Effect.promise(() => response.text()), "ok");
    }
    assert.deepStrictEqual(received, [
      { url: `${HEALTH_ROUTE}?p0_route=test-secret`, body: '{"proof":"signed"}' },
      { url: `${MINT_ROUTE}?p0_route=test-secret`, body: '{"proof":"signed"}' },
      { url: "/api/other", body: '{"proof":"signed"}' },
    ]);
    const echo = yield* Effect.promise(
      () =>
        new Promise<string>((resolve, reject) => {
          const request = NodeHttp.request(`${ingress}/ws`, {
            headers: { connection: "Upgrade", upgrade: "websocket" },
          });
          request.on("error", reject);
          request.on("upgrade", (_response, socket) => {
            socket.on("error", reject);
            socket.once("data", (chunk: Buffer) => {
              resolve(chunk.toString());
              socket.destroy();
            });
            socket.write("hello");
          });
          request.end();
        }),
    );
    assert.strictEqual(echo, "hello");
  }).pipe(Effect.scoped),
);
