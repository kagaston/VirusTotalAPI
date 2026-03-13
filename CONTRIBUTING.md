# Contributing to virustotal-api

### Setup

```bash
just sync
```

### Commands

- `just format` -- format code
- `just lint` -- lint code
- `just test` -- run all tests
- `just test virustotal` -- run tests for a specific package
- `just typecheck` -- type check
- `just check` -- run all CI checks

### Adding Dependencies

- `uv add --package virustotal <package>` -- add a runtime dependency to the virustotal member
- `uv add --dev <package>` -- add a dev dependency to the root
