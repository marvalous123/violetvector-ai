# WAR-R00M fixture sensor

This package is a cryptographic fixture for the read-only endpoint intake contract. It is not a production Windows service or a live evidence collector.

Its deliberately narrow responsibilities are:

- create an ephemeral Ed25519 identity for local tests, or load one from an explicit external path only after the caller verifies its file protection;
- sign the exact server-owned enrollment challenge;
- construct signed exact-stream capability measurements and sequence-bound primitive-fact fixtures;
- submit through a caller-provided outbound function; and
- accept only a data-only receipt.

It has no listener, polling job, command channel, remote shell, response action, payload handling, credential collection or raw-record collection.

## Private-key boundary

`loadExternal` rejects relative paths and paths inside the supplied project or runtime-data roots. It also fails unless `verifyFileProtection` returns literal `true`. `windows-key-protection.ts` provides a fail-closed Windows ACL and key/descriptor binding verifier, and `scripts/provision-sensor-key.ps1` can create a fresh external Ed25519 identity beneath `ProgramData\WAR-R00M` with protected SYSTEM/Administrators/LocalService permissions when run elevated. It rejects reparse-point destinations and never prints the private key.

This is protected external-file groundwork, not a native CNG/TPM machine keystore, code-signed service or production certificate lifecycle. The explicit backend replacement-key renewal ceremony keeps old and new identity transitions auditable and atomic.

The existing API field name `certificateFingerprintSha256` currently carries a SHA-256 fingerprint of canonical Ed25519 SPKI DER. This is a public-key identity foundation, not a delivered certificate authority, renewal protocol or production certificate lifecycle.

## Primitive-fact boundary

The fixture never supplies a detection label, rule result, command line, raw path or credential value. It signs only the declared provider/channel/event-family health measurement and normalized primitive fields accepted by the server-owned correlation service.

## Fixture honesty

The fixture produces the API's minimized-fact schema solely to test enrollment, renewal, signatures, continuity, health, loss handling and all thirty server-owned correlation definitions. Callers must use the explicit `SYNTHETIC_FIXTURE_ONLY_NO_LIVE_CLAIMS` acknowledgement. Fixture output must not be presented as live collection or production detection coverage.
