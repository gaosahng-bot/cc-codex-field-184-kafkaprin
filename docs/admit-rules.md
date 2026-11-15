# kafkaprin admit rules

## Signing input
`v1|{kid}|{principal}|{resource}|{name}|{op}|{group}|{iat}|{nonce}`

## Name safety
Reject name containing deny substrings. Topic name must startswith principals[p].topics prefix.
If resource==Group OR op in group_required_for: group must startswith principals[p].groups.

## Gates
principal exists; resource allowlist; op ∈ principals[p].ops; HMAC+revoke; time; nonce allow-only.
