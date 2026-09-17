
# Architecture

Two engines, one state store:

1. **Observation & response** — scoring, rate, reputation, session, challenge, block
2. **Morph & prediction** — envelope rotation + calibrated hypotheses

## State

JSON file (or Redis key), updated with atomic locks.

## Backends

- **File** — default
- **Redis** — better under concurrent traffic

## Main API

- `pdhpi_observe(array $request): array`
- `pdhpi_render_challenge(array $challenge): void`
- `pdhpi_state(): array`
- `pdhpi_envelope(): array`
