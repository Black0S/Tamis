# Vendored HTTPS exclusion lists

Hosts Tamis never decrypts. Embedded, not downloaded: they are active before the user
has chosen anything, so they have to work on a first launch with no network.

Refresh with [`Scripts/update-exclusions.sh`](../../../../../../Scripts/update-exclusions.sh),
then read the diff. Additions are safe; **removals reduce protection** and deserve a
look before they are committed.

| File | Upstream | Licence |
|---|---|---|
| `adguard-banks.txt` | [AdguardTeam/HttpsExclusions](https://github.com/AdguardTeam/HttpsExclusions) `exclusions/banks.txt` | MIT |
| `adguard-sensitive.txt` | same, `exclusions/sensitive.txt` | MIT |
| `adguard-issues.txt` | same, `exclusions/issues.txt` | MIT |
| `adguard-mac.txt` | same, `exclusions/mac.txt` | MIT |
| `adguard-firefox.txt` | same, `exclusions/firefox.txt` | MIT |
| `zen-darwin.txt` | [irbis-sh/zen-desktop](https://github.com/irbis-sh/zen-desktop) `internal/sysproxy/exclusions/darwin.txt` | MIT |
| `zen-common.txt` | same, `common.txt` | MIT |

The files are unmodified. Each keeps its own identity in the interface — its origin,
its licence, its counter, its update toggle — and they are combined only at match time.

`zen-darwin.txt` derives from Apple's [HT210060](https://support.apple.com/en-gb/HT210060),
which carries a *Recent changes* section worth checking when refreshing.
