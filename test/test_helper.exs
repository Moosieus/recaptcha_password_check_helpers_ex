# `:integration` tests reach the live reCAPTCHA Enterprise API, which costs a
# billed assessment and needs credentials. Run them deliberately:
#
#     mix test --only integration
#
# `:parity` tests need test/fixtures/parity_vectors.json, regenerated from
# Google's Java library via parity/regenerate.sh. They skip when it is absent.
ExUnit.start(exclude: [:integration])
