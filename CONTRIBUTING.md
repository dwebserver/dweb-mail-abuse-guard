# Contributing

Keep changes small, reviewable, and accompanied by tests. Run these checks before opening a pull request:

```sh
go fmt ./...
go vet ./...
go test -race -coverprofile=coverage.out ./internal/...
go tool cover -func=coverage.out
```

New platform adapters must keep privileged execution outside the daemon, validate identities again at the boundary, use argument arrays rather than a shell, and document rollback behavior. Parsers must not retain message bodies, subjects, passwords, or recipient addresses.

Commit messages should explain the operational reason for a change. By contributing, you agree that your work is licensed under Apache-2.0.
