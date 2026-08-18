# Parity oracle

This directory holds a small Java tool that emits byte-exact test vectors from Google's
[`recaptcha-password-check-helpers`](https://github.com/GoogleCloudPlatform/java-recaptcha-password-check-helpers)
(version 1.0.10). The vectors are the reference the Elixir reimplementation is checked against.

> **Java and Docker are needed only to regenerate the vectors.** The Elixir test suite reads the
> committed `test/fixtures/parity_vectors.json` and never invokes Java, Maven or Docker. `mix test`
> works on a machine with no JVM installed.

## Regenerating

```sh
./regenerate.sh
```

That builds the `pld-parity` image if it does not already exist, feeds `inputs.json` through it and
writes `../test/fixtures/parity_vectors.json`. Set `REBUILD=1` to force an image rebuild after
changing `pom.xml` or the Java sources.

The equivalent by hand:

```sh
docker build -t pld-parity .
docker run --rm -i pld-parity < inputs.json > ../test/fixtures/parity_vectors.json
```

## Adding cases

Append an object to the `inputs.json` array. Every field is required:

| Field | Meaning |
| --- | --- |
| `username` | Raw, un-canonicalized username |
| `password` | Raw password |
| `client_private_key_hex` | 32-byte SECP256R1 scalar, big-endian hex — the "client" cipher |
| `server_private_key_hex` | 32-byte SECP256R1 scalar, big-endian hex — the "server" cipher |

Both private keys come from the input, so the generator is deterministic: the same `inputs.json`
always produces the same `parity_vectors.json`. Nothing is randomly generated. Non-ASCII usernames
may be written as `\uXXXX` escapes; `inputs.json` is kept pure ASCII to survive any locale.

## Output

```json
{
  "helpers_version": "1.0.10",
  "vectors": [
    {
      "username": "...",
      "password": "...",
      "client_private_key_hex": "...",
      "server_private_key_hex": "...",
      "canonicalized_username": "...",
      "username_hash_hex": "...",
      "lookup_hash_prefix_hex": "...",
      "credentials_hash_hex": "...",
      "hash_into_curve_hex": "...",
      "encrypted_credentials_hash_hex": "...",
      "server_reencrypted_hex": "...",
      "client_decrypted_hex": "...",
      "rehashed_decrypted_hex": "...",
      "server_match_prefix_hex": "..."
    }
  ]
}
```

Every derived field maps to one library call:

| Key | Source |
| --- | --- |
| `canonicalized_username` | `CryptoHelper.canonicalizeUsername(username)` — strips the mail host, then drops dots and ASCII-lowercases |
| `username_hash_hex` | `CryptoHelper.hashUsername(canonical)` — SHA-256 over the canonical name plus a constant salt |
| `lookup_hash_prefix_hex` | `CryptoHelper.bucketizeUsername(canonical, 26)` — the top 26 bits of the username hash, zero-padded to 4 bytes |
| `credentials_hash_hex` | `CryptoHelper.hashUsernamePasswordPair(canonical, password, scrypt)` — scrypt(N=4096, r=8, p=1, 32 bytes) |
| `hash_into_curve_hex` | `clientCipher.hashIntoTheCurve(credentials_hash)` — compressed SECP256R1 point |
| `encrypted_credentials_hash_hex` | `clientCipher.encrypt(credentials_hash)` |
| `server_reencrypted_hex` | `serverCipher.reEncrypt(encrypted_credentials_hash)` |
| `client_decrypted_hex` | `clientCipher.decrypt(server_reencrypted)` |
| `rehashed_decrypted_hex` | `CryptoHelper.hashBlindedHash(client_decrypted)` — SHA-256, the value the service's prefixes are matched against |
| `server_match_prefix_hex` | first 20 bytes of `sha256(serverCipher.encrypt(credentials_hash))` |

The generator asserts the commutativity the protocol depends on before emitting anything:
`clientCipher.decrypt(serverCipher.reEncrypt(clientCipher.encrypt(h)))` must equal
`serverCipher.encrypt(h)`, and `server_match_prefix_hex` must be a prefix of
`rehashed_decrypted_hex`. A mismatch aborts with a non-zero exit rather than writing a bad fixture.

## Layout

- `pom.xml` — one dependency (the helpers library), shaded into a standalone jar. JSON is
  hand-rolled in `Json.java` to keep the dependency surface at exactly one artifact.
- `src/main/java/org/pldparity/VectorGen.java` — reads the input array from stdin, writes the vector
  object to stdout.
- `src/main/java/org/pldparity/Json.java` — minimal JSON reader/writer. Output escapes every
  non-ASCII character as `\uXXXX`, so the fixture is pure ASCII and diffs cleanly.
- `Dockerfile` — Maven build stage on `maven:3.9.9-eclipse-temurin-21`, runtime on
  `eclipse-temurin:21-jre`.
