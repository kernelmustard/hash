# hash
(useless) reimplementation of common hashing algorithms

# dev
- Trying to figure out how to parse args in a certain order, right now just specify hashing algo (or --all) last.
- No clue why, but `--string` with `--crc32` gives an incorrect value

# sources
- https://www.w3.org/TR/png/#D-CRCAppendix
- https://users.ece.cmu.edu/~koopman/crc/index.html
- https://fuchsia.googlesource.com/third_party/wuffs/+/HEAD/std/crc32/README.md

- https://datatracker.ietf.org/doc/html/rfc1321
- https://cs.indstate.edu/~fsagar/doc/paper.pdf
- https://github.com/Zunawe/md5-c/