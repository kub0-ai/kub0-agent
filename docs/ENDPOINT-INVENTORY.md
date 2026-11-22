# Tenant inventory status

The view describes API-reported kub0 endpoint inventory, not an audit of every
installed kub0d binary. Only `enforcing`, `monitoring`, and `down` are recognized
server states; unsupported strings remain unknown.

Client policy in `js/Endpoints.js`: an otherwise online row becomes Offline at
exactly 600,000 ms since lastSeen. `ENDPOINT_FUTURE_SKEW_MS` allows at most 60,000 ms
of positive clock skew, clamping tolerated negative age to zero. Larger future
observations, missing/invalid dates, and invalid clocks yield unknown status.
An explicit down report can remain Offline without establishing a fresh lastSeen.

The last successful inventory displays its full local date and age, also when a
refresh fails. Missing, invalid, or more-than-60-second-future inventory timestamps
never imply fresh success. Failed refreshes preserve the last-good rows and date;
valid empty inventories clear rows. Disconnect/account replacement clears prior
identity data. Offline rows remain searchable with version, architecture and
kernel fields; filters and row selection toggle off on a second activation.

`blocksActive` counts apps with endpoint-owner IP entries. It is not fleet kernel
rules, ranges, packets, or an enforcement total. Reported zero differs from an
unreported value. No API vocabulary or additional enforcement inference is added.

## Verification

Run all Node model regressions and `cargo test --workspace`. Parser tests cover
unsupported states and zero/unreported counts. `tests/qml/run-runtime.sh` runs the
private actual EndpointsView fixture, including visible status/count wording,
full retained date and age after failure, far-future freshness, empty inventory,
selection/deselection, and disconnect gating. The existing runner provides private
HOME/config/state/runtime, canonical fake helper masking, network isolation,
preference preservation and bounded processes. Do not run it outside its namespace.

The native deadline timer updates on the next available QML animation frame,
not with a real-time millisecond guarantee. No live account or installed
service is used.
