Drop REAL CloudTrail event JSON files here (e.g. copy experiments/a44/out/*.json after redacting).
Name them `denied-*.json` for events with an errorCode, `allowed-*.json` otherwise.
tests/real-fixtures.test.ts picks them up automatically. Keep account ids synthetic/redacted if the repo is shared.
