# Testing

Three layers, deliberately separated:

```
mix test                    # unit + parity, no network, no credentials
mix test --only integration # the live canary, bills one assessment
parity/regenerate.sh        # refresh parity vectors from Google's Java library
```

**Unit tests** cover the curve arithmetic against OTP itself: `:crypto`'s ECDH performs exactly the scalar multiplication implemented here, so `generate_key/3` validates `k * G` and `compute_key/4` validates `k * P` for arbitrary `P`. The full request/response cycle runs against a locally simulated service, so both the leaked and not-leaked paths are covered without a network.

**Parity tests** compare every pipeline stage — canonicalization, both hashes, the bucket prefix, hash-to-curve, blinding, re-encryption, unblinding — against byte-exact output from Google's Java implementation. A failure names the stage that diverged rather than just going red. Java and Docker are needed only to regenerate the fixtures; the committed JSON is all the suite reads.

**The canary** is the only thing that can detect the protocol changing underneath us. Fixtures prove agreement with Google's *library*; the canary proves agreement with Google's *server*. Run it on a schedule:

```
RECAPTCHA_PROJECT_ID=... GOOGLE_CLOUD_API_KEY=... mix test --only integration
```