# engine: Adaptive Connect decisions

The choices every Colitu app makes the same way, written once in Go.

| Decision | Code | Vectors |
|---|---|---|
| Server order of automatic mode | `ranking.go` (`Rank`) | `testdata/ac-vectors/ranking.json` |

`testdata/ac-vectors` is the canonical copy of the shared test vectors. The
Android, iOS, Windows and Linux apps run the same files against their own
code (`sync-vectors.sh` copies them over); a change of a rule starts here, in
the vectors, and every app follows. Later the apps call this package instead
(gomobile for Android/iOS, a C shared library for Windows/Linux).

```
go test ./engine/
```
