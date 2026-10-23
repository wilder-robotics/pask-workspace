# 0003. Hardware appraisal of AMD SEV-SNP on Milan

- Status: Accepted by the architect (ChatGPT) on 2026-10-23.
- Implementation: not done.
- This record is a selection. It does not claim that native hardware appraisal exists.

## Selection

The first hardware appraisal target is AMD SEV-SNP on Milan. Milan is the processor family named by the architect. This record does not name a board or an ordering identifier.

Appraisal is a separate native-evidence API in `pask-attest`. It is not a new interpretation of the existing quote verifier.

An opaque quote must never count as successful hardware appraisal. A matching digest must never count as successful hardware appraisal.

## Preserved limitation

[`KNOWN-LIMITATIONS.md`](../../KNOWN-LIMITATIONS.md) section 5.2a records that published `pask-attest` 0.1.0 accepts `amd.sev-snp` as a class label and an opaque SHA-256 digest, and that a quote carrying that digest verifies with no evidence bytes on disk. The 2026-09-29 witness experiment is not hardware appraisal under this selection. This decision does not change the crate or that limitation.
