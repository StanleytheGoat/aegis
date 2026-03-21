# Contributing to Aegis

## Development Setup

```bash
git clone <repo-url>
cd aegis
npm install
cp .env.example .env   # add your RPC URLs and API keys
npm run build
```

Requires Node.js 18 or later.

## Running Tests

```bash
npm test                 # 123 TypeScript tests (vitest)
npm run test:contracts   # 42 Solidity tests (Hardhat)
```

Run both before opening a pull request.

## Project Structure

- `src/` -- MCP server source code (TypeScript, ES modules)
- `contracts/` -- Solidity smart contracts, compiled with Hardhat
- `integrations/` -- Third-party integrations (ElizaOS, AgentKit, Flaunch)
- `site/` -- Landing page
- `demo/` -- Demo scripts (`npm run demo` catches a honeypot token)
- `dist/` -- Compiled output from `npm run build`

## Submitting a Pull Request

1. Branch from `main`. Use a descriptive branch name (`fix/reentrancy-check`, `feat/new-detector`).
2. Write tests for any new functionality.
3. Run `npm test` and `npm run test:contracts`. Both must pass.
4. Run `npm run build` to confirm the project compiles cleanly.
5. Open a PR with a clear description of what changed and why.

## Code Style

- TypeScript strict mode is enabled. Do not weaken it.
- Use ES module imports (`import`/`export`), not CommonJS.
- Do not use `console.log` in `src/`. Use the project's logging utilities instead.
- Keep functions focused and files short.

## Security

A pre-push hook (installed automatically via husky during `npm install`) scans for leaked secrets before code reaches the remote. Do not bypass it.

If you discover a security vulnerability, do not open a public issue. See [SECURITY.md](./SECURITY.md) for responsible disclosure instructions.
