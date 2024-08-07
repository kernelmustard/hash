# hash
toy reimplementation of common hashing algorithms

# usage
## hash
- hash provided string or file using crc32, md5, sha1, sha256, or all of the above
- compile with `make` or `make dev` (if you want to poke around the binary)
## test
- not of much use to the user, but it hashes known strings and compares them against the known correct hash to verify the algorithm implementation
- compile with `make test`

# sources
## CRC32
- https://www.w3.org/TR/png/#D-CRCAppendix
- https://users.ece.cmu.edu/~koopman/crc/index.html
- https://fuchsia.googlesource.com/third_party/wuffs/+/HEAD/std/crc32/README.md
## MD5
- https://datatracker.ietf.org/doc/html/rfc1321
- https://cs.indstate.edu/~fsagar/doc/paper.pdf
- https://github.com/Zunawe/md5-c/
## SHA1
- https://datatracker.ietf.org/doc/html/rfc3174 
- https://github.com/clibs/sha1
## SHA256
- https://datatracker.ietf.org/doc/html/rfc6234
- https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c