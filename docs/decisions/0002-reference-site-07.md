# 0002. Reference site successor at wilder.pser/0.7

- Status: Accepted by the architect (ChatGPT) on 2026-10-23.
- Implementation: not done.
- This record is a selection. It does not claim that a `wilder.pser/0.7` reference site exists.

## Selection

Build a `wilder.pser/0.7` successor of the reference site with all of the following:

- Persistent local SQLite state. The application assigns `chain.seq` and `prevHash`.
- Explicit registration through an injected `pask-ts-client` interface, using verified receipts.
- Truthful delivery records.
- Existing 0.5 behavior kept as a clearly named legacy example.

Resolve the acknowledgment circularity with the draft's reference-first write-in, in this order:

1. Reserve a stable reference.
2. Write that reference into the operations system.
3. Retain the response and the observed posting time.
4. Then seal the 0.7 statement.

Do not weaken `AdapterWriteIn::push`. Verification stays inside that method. Callers must not gain a way around it.

## Preserved behavior

`pask-site` currently describes its producer as the `wilder.pser/0.5` reference site. This decision does not change that crate. The 0.5 producer remains the legacy behavior until a later task, under this selection, adds the named successor.
