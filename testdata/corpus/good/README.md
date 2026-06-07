# Corpus: good/ (false-positive guard)

Each `.json` file in this directory is a fixture for a **legitimate** package. The JSON shape is:

```json
{
  "data": { <PackageData fields — see below> },
  "max_tier": "<TIER>"
}
```

`max_tier` is a **ceiling**: the engine must score this package at or *below* the stated tier. If it scores higher, the test fails as a **false positive** — the engine is flagging a safe package as suspicious.

## JSON shape for `data`

`model.PackageData` embeds `Candidate` **anonymously**, so `encoding/json` promotes `Name` and `Version` to the **top level** of the `data` object. You **must** write:

```json
"data": {
  "Name": "some-package",
  "Version": "1.2.3",
  "Registry": { ... },
  "Scripts": { ... },
  "Files": { ... }
}
```

Do **not** nest them under a `"Candidate"` key — that key is ignored by `encoding/json` for embedded structs, leaving `Name` empty and causing the test to fail with a loud error.

## Adding new fixtures

1. Pick a well-known, long-lived package with a public repository and high download counts.
2. Fill in realistic `Registry` fields (old `FirstPublished`, high `WeeklyDownloads`, non-empty `Repository`).
3. Set `max_tier` conservatively — if the package has an `install` hook for native compilation, `"LOW"` is appropriate; a pure-JS package with no hooks should use `"CLEAR"`.
4. **Sanitize**: never commit real credential values, internal hostnames, or anything sensitive from a live investigation. Fixture data is public.
