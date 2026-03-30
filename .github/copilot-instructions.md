# Copilot Instructions

This is a Go project using Go modules.

## Code conventions

- Follow standard Go conventions (gofmt, go vet)
- Use golangci-lint with the project's `.golangci.yaml`
- Prefer returning errors over panicking
- Use the repository-standard error helpers from `github.com/pkg/errors`
	(`errors.Wrap`, `errors.Wrapf`, `errors.Errorf`). CI rejects `fmt.Errorf`.
- Keep functions focused and under 60 lines

## Testing

- All new code must include tests
- Use table-driven tests where appropriate
- Target at least 80% coverage
- Run `go test ./... -race` before committing

### Test documentation

Every test function needs a doc comment structured **outside-in**:
1. What the tested code achieves for the end user (in user terms)
2. Which module or feature area the tested code belongs to
3. What specific behavior this test verifies

For table-driven tests, document the overall function and give each
sub-test a descriptive assertion-style name.

### Function and method documentation

Every exported function/method needs a godoc comment covering:
1. Concise summary (starting with the function name)
2. Parameter specification (type, valid range, purpose)
3. Return values (success and error cases)
4. Usage context — when/why a caller would use this, related functions
5. Optional: inline example or reference to Example* function

Write documentation like good JavaDoc but with more context about
how and when to use the function, not just what it does.

## Dependencies

- Minimize external dependencies
- Run `go mod tidy` after changes
- Dependencies are managed via Renovate

## Security

- Never commit secrets or credentials
- The gosec linter is active — do not suppress findings without justification
- Validate all external input
