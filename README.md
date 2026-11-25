# T3 Connect bridge (p0code plugin)

An unofficial, off-by-default [p0code](https://github.com/p0code/p0code) server plugin that links a p0code environment to the official T3 Connect service, so T3 Code apps signed in to your T3 account (including the store mobile app, with push notifications) can reach it.

It is mounted as the `plugins/t3-connect-bridge` git submodule of p0code and built inside that workspace, where it imports `@t3tools/plugin-api`, `@t3tools/contracts` and `@t3tools/shared`. Develop it from a p0code checkout:

```sh
git clone --recurse-submodules https://github.com/p0code/p0code
cd p0code && vp i
vp run --filter @t3tools/plugin-t3-connect-bridge typecheck
```

The host provides `PluginContext.routes.secret` when `http:routes` is declared. Upstream's managed relay fixes the public origin and callback paths, so registration cannot carry custom webhook URLs or headers. The bridge registers a scoped loopback ingress as the tunnel destination; it adds `p0_route` only to health and credential-mint requests forwarded to the host. Other HTTP requests and WebSocket upgrades pass through unchanged. The relay's signed proofs are still required by both callbacks.

## License

MIT. See [LICENSE](LICENSE).
