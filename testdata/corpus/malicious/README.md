# Corpus: malicious/ (false-negative guard)

Each `.json` file in this directory is a fixture for a **known-malicious or synthetic-malicious** package. The JSON shape is:

```json
{
  "data": { <PackageData fields — see below> },
  "min_tier": "<TIER>"
}
```

`min_tier` is a **floor**: the engine must score this package at or *above* the stated tier. If it scores lower, the test fails as a **false negative** — the engine missed a package that should have been flagged.

## JSON shape for `data`

`model.PackageData` embeds `Candidate` **anonymously**, so `encoding/json` promotes `Name` and `Version` to the **top level** of the `data` object. You **must** write:

```json
"data": {
  "Name": "some-package",
  "Version": "0.0.1",
  "Registry": { ... },
  "Scripts": { ... },
  "Files": { ... }
}
```

Do **not** nest them under a `"Candidate"` key — that key is ignored by `encoding/json` for embedded structs, leaving `Name` empty and causing the test to fail with a loud error.

## Adding new fixtures safely

1. **Strip all real C2 endpoints and credentials.** Replace exfil hostnames with `evil.tld`-style placeholders (e.g. `https://evil.tld/collect`). Replace any real tokens, keys, or passwords with `REDACTED` or a clearly fake value.
2. **Never commit a working payload.** The fixture must not be functional malware — its purpose is to exercise the *detector*, not to reproduce the attack. Destructive or exfiltrating code must be neutered.
3. Set `min_tier` to the lowest tier the engine *must* reach. Use `"HIGH"` for typosquats with credential exfil, `"CRITICAL"` only when both a credential read and egress are present and the engine is expected to emit `inspect.exfil`.
4. Name the file descriptively: `<package-name>-<attack-type>.json` (e.g. `reqeusts-exfil.json`, `lodas-depconfusion.json`).
5. Cite a public source (CVE, npm advisory, Phylum/Socket report) in a comment field if available, so reviewers can verify the sample is real.
