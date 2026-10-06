## What and why

<!-- What this changes and the problem it solves. Link the issue. -->

## Checklist

- [ ] Tests cover the change (a bug fix includes the test that would have caught it)
- [ ] For a security check: on the side's list in `test/mutations/`, and `scripts/mutate.py` catches it
- [ ] A new refusal reason is in `REASONS`, public only if the caller learns nothing it didn't send
- [ ] README (options, tables, events, errors) and docs/interop.md updated
- [ ] `[Unreleased]` in CHANGELOG.md updated
- [ ] A DECISIONS.md entry, if this makes a design choice or records an interop finding
- [ ] Breaking for users, or for the other side of the exchange? Checked against docs/versioning.md
- [ ] No real keys, client secrets, tokens or personal data anywhere
