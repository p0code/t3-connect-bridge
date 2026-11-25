# Contributing

This is the T3 Connect bridge plugin for [p0code](https://github.com/p0code/p0code): an
off-by-default plugin that links a p0code environment to the official T3 Connect service.

Contributions are welcome — issues and small, focused PRs. I'm one person and this is a side
project, so reviews and replies can take a while. Please be patient, and don't ping repeatedly; one
polite bump after a couple of weeks is fine.

## Setup

The plugin is mounted as the `plugins/t3-connect-bridge` submodule of p0code and builds inside that
workspace (it imports `@t3tools/plugin-api`, `@t3tools/contracts` and `@t3tools/shared`):

```sh
git clone --recurse-submodules https://github.com/p0code/p0code
cd p0code
pnpm install
pnpm --filter @t3tools/plugin-t3-connect-bridge typecheck
pnpm --filter @t3tools/plugin-t3-connect-bridge test
```

## What makes a PR easy to land

- One thing per PR, with tests for behaviour changes.
- Conventional-commit-ish messages (`fix: ...`, `feat: ...`, `docs: ...`).
- No drive-by refactors or reformatting.
- Don't log tokens or connection secrets.

## License

MIT. By contributing you agree that your work is released under the MIT license. See
[LICENSE](LICENSE).
