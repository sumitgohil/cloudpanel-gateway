## Summary

Describe the problem and the change.

## Security impact

- [ ] No security-relevant change
- [ ] New/changed scope, policy gate, privileged protocol, validation, artifact handling, or audit behavior (describe below)

## Validation

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] Documentation/OpenAPI/MCP descriptions updated where needed
- [ ] Manually tested on a disposable CloudPanel VM, if applicable

## Checklist

- [ ] No tokens, passwords, private keys, customer data, or unredacted logs included
- [ ] Change is focused and has a rollback/failure behavior where needed
- [ ] Linked issue or explained why one is unnecessary
