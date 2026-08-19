# Testing

### Unit + Parity (no network or credentials required)
```sh
mix test
```

Cover the curve arithmetic against OTP itself: `:crypto`'s ECDH performs exactly the scalar multiplication implemented here, so `generate_key/3` validates `k * G` and `compute_key/4` validates `k * P` for arbitrary `P`. The full request/response cycle runs against a locally simulated service, so both the leaked and not-leaked paths are covered without a network.

### Live Canary (network and credentials required)
```sh
RECAPTCHA_PROJECT_ID="..." \
  GOOGLE_CLOUD_ACCESS_TOKEN=$(gcloud auth print-access-token) \
  mix test --only integration
```

The only thing that can detect the protocol changing underneath us. Fixtures prove agreement with Google's *library*; the canary proves agreement with Google's *server*. Worth running on a schedule rather than on demand.

The project also needs the reCAPTCHA Enterprise API enabled and password defense available on its tier.

### Refresh parity vectors from `GoogleCloudPlatform/java-recaptcha-password-check-helpers`
```sh
parity/regenerate.sh
```

Compare every pipeline stage against byte-exact output from Google's Java implementation. A failure names the stage that diverged rather than just going red. Java and Docker are needed only to regenerate the fixtures; the committed JSON is all the suite reads.

The generator resolves `com.google.cloud:recaptcha-password-check-helpers` from Maven Central rather than cloning a repo, so the version pinned in `parity/pom.xml` is what parity is measured against.

## On macOS
Prefix these commands with `env -u LDFLAGS` if you export `LDFLAGS` globally. The scrypt NIF fails to link otherwise — see the build notes in `README.md`.
