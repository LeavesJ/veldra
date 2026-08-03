# Contributing to ReserveGrid OS

ReserveGrid OS is released under the Veldra Source Available License v1.0,
which restricts modification, derivative works, and redistribution. External
contributions are accepted **by invitation only** and require written
authorization from the project owner before any work begins.

## How to Contribute

1. Contact jarrondeng@veldra.org describing the change you would like to make
2. Wait for written authorization before forking or modifying the codebase
3. Once authorized, follow the workflow and conventions below

Unsolicited pull requests from unauthorized contributors will be closed without
review.

## Authorized Contributor Workflow

1. Fork the repository (only after written authorization)
2. Create a feature branch from `dev`
3. Make your changes following the conventions below
4. Open a pull request against `dev`

## Development Setup

```bash
# Install Rust 2024 edition (1.92+)
rustup install 1.92
rustup default 1.92

# Build the rg-dashboard frontend first. rust-embed bakes
# services/rg-dashboard/frontend/dist into the rg-dashboard binary, and
# dist/ is gitignored, so a fresh clone cannot build or test the
# workspace until this step runs (matches the CI `build-test` job).
cd services/rg-dashboard/frontend
npm ci
npm run build
cd -

# Build the workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Branch Naming

Use descriptive prefixes:

- `feat/` for new features
- `fix/` for bug fixes
- `refactor/` for structural changes with no behavior change
- `test/` for test additions or improvements
- `docs/` for documentation changes
- `ci/` for CI/CD changes

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `style`, `perf`, `chore`

Scope should be the crate name when applicable (e.g., `pool-verifier`,
`sv2-gateway`, `rg-auth`).

## Pull Request Requirements

Every PR must:

1. Pass CI (build, test, clippy, fmt, audit, deny, vet, secrets scan)
2. Include tests for new behavior
3. Not break existing tests
4. Not introduce new clippy warnings
5. Target `dev` via a feature branch

## Code Conventions

- **Edition:** Rust 2024
- **Line width:** 100 characters (enforced by `rustfmt.toml`)
- **Error handling:** fail fast with explicit errors, no silent fallbacks
- **Logging:** use `tracing` with structured fields
- **Env vars:** prefix with `VELDRA_`
- **Reason codes:** canonical `snake_case`, stable across protocol/verifier/exports
- **Dependencies:** justify new additions; prefer the existing stack (tokio, reqwest, serde, clap, tracing)

## Testing

- Unit tests live alongside the code in `#[cfg(test)]` modules
- Integration tests live in `scripts/` and run via Docker Compose
- Load tests use `rg-load-test` against the compose stack

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

Do not introduce `unsafe` code. The workspace denies it via lint config:

```toml
[workspace.lints.rust]
unsafe_code = "deny"
```

## Intellectual Property

By submitting a contribution, you grant Veldra, Inc. a perpetual, worldwide,
irrevocable, royalty free, sublicensable license to use, reproduce, modify,
distribute, and create derivative works from your contribution for any purpose,
as described in Section 6 of the [LICENSE](LICENSE). You represent that you have
the right to grant this license and that your contribution does not infringe any
third party rights.
