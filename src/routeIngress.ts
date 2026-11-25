// @effect-diagnostics nodeBuiltinImport:off -- The tunnel ingress must proxy HTTP upgrades as well as requests.
import * as NodeHttp from "node:http";
import * as NodeNet from "node:net";
import { PluginError } from "@t3tools/plugin-api";
import * as Effect from "effect/Effect";

import { HEALTH_ROUTE, MINT_ROUTE } from "./relayProtocol.ts";

export function routeUrl(origin: string, path: string, secret: string): URL {
  const url = new URL(origin);
  const incoming = new URL(path, "http://ingress.invalid");
  url.pathname = incoming.pathname;
  url.search = incoming.search;
  if (url.pathname === HEALTH_ROUTE || url.pathname === MINT_ROUTE) {
    url.searchParams.set("p0_route", secret);
  }
  return url;
}

// Upstream chooses the public origin and fixed callback paths. Its registration protocol
// only lets us choose the loopback destination, so attach the bearer at that boundary.
export const makeRouteIngress = (origin: string, secret: string) =>
  Effect.acquireRelease(
    Effect.callback<
      {
        readonly server: NodeHttp.Server;
        readonly origin: string;
        readonly sockets: Set<NodeNet.Socket>;
      },
      PluginError
    >((resume) => {
      const target = new URL(origin);
      const sockets = new Set<NodeNet.Socket>();
      const server = NodeHttp.createServer((request, response) => {
        let url: URL;
        try {
          url = routeUrl(origin, request.url ?? "/", secret);
        } catch {
          response.writeHead(400);
          response.end();
          return;
        }
        const upstream = NodeHttp.request(
          url,
          {
            method: request.method,
            headers: request.headers,
          },
          (incoming) => {
            response.writeHead(incoming.statusCode ?? 502, incoming.headers);
            incoming.pipe(response);
            incoming.on("error", () => response.destroy());
          },
        );
        upstream.on("error", () => {
          if (response.headersSent) {
            response.destroy();
            return;
          }
          response.writeHead(502);
          response.end();
        });
        request.on("aborted", () => upstream.destroy());
        response.on("close", () => upstream.destroy());
        request.pipe(upstream);
      });
      server.on("upgrade", (request, socket, head) => {
        const upstream = NodeNet.connect(
          Number(target.port || 80),
          target.hostname.replace(/^\[(.*)\]$/u, "$1"),
        );
        upstream.on("connect", () => {
          upstream.write(`${request.method} ${request.url} HTTP/${request.httpVersion}\r\n`);
          for (let i = 0; i < request.rawHeaders.length; i += 2) {
            upstream.write(`${request.rawHeaders[i]}: ${request.rawHeaders[i + 1]}\r\n`);
          }
          upstream.write("\r\n");
          upstream.write(head);
          socket.pipe(upstream);
          upstream.pipe(socket);
        });
        upstream.on("error", () => socket.destroy());
        socket.on("error", () => upstream.destroy());
        socket.on("close", () => upstream.destroy());
      });
      server.on("connection", (socket) => {
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
      });
      server.once("error", () =>
        resume(
          Effect.fail(new PluginError({ message: "Could not start the T3 Connect ingress." })),
        ),
      );
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (address !== null && typeof address !== "string") {
          resume(Effect.succeed({ server, origin: `http://127.0.0.1:${address.port}`, sockets }));
        }
      });
      return Effect.sync(() => server.close());
    }),
    ({ server, sockets }) =>
      Effect.sync(() => {
        for (const socket of sockets) socket.destroy();
        server.closeAllConnections();
        server.close();
      }),
  ).pipe(Effect.map((ingress) => ingress.origin));
