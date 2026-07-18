# Contributing

Thanks for contributing to CloudPanel Gateway. This project handles privileged
server operations, so clarity, tests, and conservative changes matter.

## Before opening an issue or pull request

- Search existing issues and pull requests first.
- Do not include tokens, private keys, database credentials, certificate
  material, customer domains, raw sensitive logs, or production IP addresses.
- Report security vulnerabilities privately under [SECURITY.md](SECURITY.md),
  not through a public issue.
- For a feature proposal, explain the CloudPanel behavior, least-privilege
  scope, typed schema, validation rules, failure behavior, and test plan.

## Development workflow

1. Fork the repository and branch from `main`.
2. Keep the change focused. Do not mix refactors with behavior changes.
3. Add or update tests for validation, authorization, error handling, and
   redaction. Privileged execution must never use a shell.
4. Run the required checks:

   ```bash
   gofmt -w .
   go test ./...
   go vet ./...
   ```

5. Update user-facing documentation, OpenAPI/MCP descriptions, and CLI help
   when the public behavior changes.

## Pull request requirements

- Use a descriptive title and explain the problem and solution.
- Link the relevant issue where applicable.
- State how the change was tested and any CloudPanel version assumptions.
- Call out security implications, new scopes, policy-gated behavior, migrations,
  or rollback steps.
- Keep secrets out of commits, screenshots, terminal output, and CI logs.
- Ensure GitHub Actions are green before requesting review.

Maintainers may request a smaller patch, additional test coverage, a security
review, or manual verification on a disposable CloudPanel VM.

## Commit guidance

Use concise conventional-style messages, for example:

```text
feat: add typed PHP settings update
fix: reject symlinked application logs
docs: clarify release verification
```

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
