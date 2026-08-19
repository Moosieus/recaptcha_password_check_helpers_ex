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
project = "my_super_cool_gcp_project"
token = "my_super_secret_bearer_token"

# https://www.youtube.com/watch?v=gYs9nS8LlZ8
{:ok, verification} =
  RecaptchaPasswordCheck.create_verification("GabeN@valvesoftware.com", "MoolyFTW")

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
    headers: [{"authorization", "Bearer " <> token}],
    receive_timeout: 5_000
  )

leak = response.body["privatePasswordLeakVerification"]

%{
  "privatePasswordLeakVerification" => %{
    "reencryptedUserCredentialsHash" => reencrypted_user_credentials_hash,
    "encryptedLeakMatchPrefixes" => encrypted_leak_match_prefixes
  }
} = response.body

reencrypted_user_credentials_hash = Base.decode64!(reencrypted_user_credentials_hash)
encrypted_leak_match_prefixes = Enum.map(encrypted_leak_match_prefixes, &Base.decode64!/1)

# was the canonicalized-username and password combination leaked?
RecaptchaPasswordCheck.leaked?(
  verification,
  reencrypted_user_credentials_hash,
  encrypted_leak_match_prefixes
)
```

Get the bearer token above from `goth`, or send an API key instead — though a key brings application and API restrictions that fail with an opaque `API key not valid`.

Password defense requires the **Premium** tier. Assessments are free up to 10,000 per calendar month per organization, then $8 flat to 100,000.

## Testing

See [TESTING.md](TESTING.md).

## Build notes

**macOS.** The scrypt NIF's Makefile assigns its Darwin link flags with `?=`, so an inherited `LDFLAGS` replaces rather than extends them and the NIF fails to link with undefined `_enif_*` symbols. If you export `LDFLAGS` globally (for example for `libpq`), either compile with `env -u LDFLAGS mix deps.compile scrypt` or append `-undefined dynamic_lookup` to your exported value.

**Docker.** Builds cleanly on Debian bookworm for both amd64 and arm64; the `elixir:*-otp-27` images already carry `cc` and `make`. The dependency is rebar3-managed, so the build stage needs `mix local.rebar --force`, and `priv/scrypt.so` is produced at `mix deps.compile` time — a multi-stage build must carry the compiled artefact forward, not just `deps` source.

## Security notes

Scalar multiplication uses a Montgomery ladder, so the sequence of group operations does not depend on the scalar's bits. It is not constant time in the strict sense — the BEAM's bignum arithmetic is variable time — and it is not intended to be. The scalar is an ephemeral per-verification blinding factor, and recovering it would require timing the local process precisely while also observing the outbound request.

Passwords are never stored on the `Verification` struct, and inspecting it redacts the private key, keeping both out of logs and crash reports.

## Attribution

A port of Apache-2.0 licensed work by Google LLC. See `NOTICE`.
