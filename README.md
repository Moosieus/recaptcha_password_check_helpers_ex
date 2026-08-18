# RecaptchaPasswordCheck

An Elixir port of Google's `recaptcha-password-check-helpers`, the client-side cryptography for reCAPTCHA's [private password leak
check](https://docs.cloud.google.com/recaptcha/docs/check-passwords).

## Installation

```elixir
def deps do
  [{:recaptcha_password_check_helpers_ex, "~> 0.1"}]
end
```

## Example Usage

```elixir
api_key = "my_super_secret_api_key"
project = "my_super_cool_gcp_project"

verification = RecaptchaPasswordCheck.create_verification("user@example.com", "hunter2")

%{
  lookup_hash_prefix: lookup_hash_prefix,
  encrypted_user_credentials_hash: encrypted_user_credentials_hash
} = verification

body = %{
  "privatePasswordLeakVerification" => %{
    "lookupHashPrefix" => Base.encode64(lookup_hash_prefix),
    "encryptedUserCredentialsHash" => Base.encode64(encrypted_user_credentials_hash)
  }
}

response =
  Req.post!("https://recaptchaenterprise.googleapis.com/v1/projects/#{project}/assessments",
    json: body,
    headers: [{"x-goog-api-key", api_key}],
    receive_timeout: 5_000
  )

leak = response.body["privatePasswordLeakVerification"]

result =
  RecaptchaPasswordCheck.verify(
    verification,
    Base.decode64!(leak["reencryptedUserCredentialsHash"]),
    Enum.map(leak["encryptedLeakMatchPrefixes"], &Base.decode64!/1)
  )

result.leaked?
```

Hold on to the `verification` struct across the round trip — it carries the ephemeral key that decrypts the reply. Google recommends budgeting around 500ms for the exchange.

This library deliberately stops at the cryptography, mirroring Google's own helpers: no HTTP, no authentication, no assessment payload. Authenticate with an API key as above, or with `goth` and a bearer token.

Password defense requires the **Premium** tier. Assessments are free up to 10,000 per calendar month per organization, then $8 flat to 100,000.

## What the verdict does and does not mean

`leaked?` is the entire answer. There is no breach name, date, or count — the protocol cannot carry them.

Matching is looser than it looks. Canonicalization discards the email host, so `alice@example.com` and `alice@other.test` collide:

```elixir
RecaptchaPasswordCheck.canonicalize_username("Alice.Smith@example.com")
#=> "alicesmith"
```

A reported leak therefore means *this local part and password appeared together somewhere*, which catches cross-site password reuse but is not proof that this particular account was breached. Worth knowing before wiring it to a forced reset.

## Build notes

**macOS.** The scrypt NIF's Makefile assigns its Darwin link flags with `?=`, so an inherited `LDFLAGS` replaces rather than extends them and the NIF fails to link with undefined `_enif_*` symbols. If you export `LDFLAGS` globally (for example for `libpq`), either compile with `env -u LDFLAGS mix deps.compile scrypt` or append `-undefined dynamic_lookup` to your exported value.

**Docker.** Builds cleanly on Debian bookworm for both amd64 and arm64; the `elixir:*-otp-27` images already carry `cc` and `make`. The dependency is rebar3-managed, so the build stage needs `mix local.rebar --force`, and `priv/scrypt.so` is produced at `mix deps.compile` time — a multi-stage build must carry the compiled artefact forward, not just `deps` source.

## Security notes

Scalar multiplication uses a Montgomery ladder, so the sequence of group operations does not depend on the scalar's bits. It is not constant time in the strict sense — the BEAM's bignum arithmetic is variable time — and it is not intended to be. The scalar is an ephemeral per-verification blinding factor, and recovering it would require timing the local process precisely while also observing the outbound request.

Passwords are never stored on the `Verification` struct, and inspecting it redacts the private key, keeping both out of logs and crash reports.

## Attribution

A port of Apache-2.0 licensed work by Google LLC. See `NOTICE`.
