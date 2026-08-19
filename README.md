# RecaptchaPasswordCheck

An Elixir workalike of Google's [`java-recaptcha-password-check-helpers`](https://github.com/GoogleCloudPlatform/java-recaptcha-password-check-helpers), the client-side cryptography for reCAPTCHA's [private password leak
check](https://docs.cloud.google.com/recaptcha/docs/check-passwords).

## Installation

```elixir
def deps do
  [{:recaptcha_password_check_helpers_ex, "~> 0.1"}]
end
```

## Example Usage

<!-- MDOC !-->

```elixir
project = "my_super_cool_gcp_project"
token = "my_super_secret_bearer_token"

# https://www.youtube.com/watch?v=gYs9nS8LlZ8
{:ok, verification} =
  RecaptchaPasswordCheck.create("GabeN@valvesoftware.com", "MoolyFTW")

# Bring your own http/proto3 client
body = %{
  "privatePasswordLeakVerification" => %{
    "lookupHashPrefix" => Base.encode64(verification.lookup_hash_prefix),
    "encryptedUserCredentialsHash" =>
      Base.encode64(verification.encrypted_user_credentials_hash)
  },
  # "otherReCaptchaAssessmentFields" => "..."
}

response =
  Req.post!("https://recaptchaenterprise.googleapis.com/v1/projects/#{project}/assessments",
    json: body,
    headers: [{"authorization", "Bearer " <> token}],
    receive_timeout: 5_000
  )

if response.status == 200 do
  object = Map.fetch!(response.body, "privatePasswordLeakVerification")

  RecaptchaPasswordCheck.leaked?(
    verification,
    Base.decode64!(Map.fetch!(object, "reencryptedUserCredentialsHash")),
    object |> Map.get("encryptedLeakMatchPrefixes", []) |> Enum.map(&Base.decode64!/1)
  )
end
```

Get the bearer token above from `goth`, or send an API key instead — though a key brings application and API restrictions that fail with an opaque `API key not valid`.

<!-- MDOC !-->

## Testing

See [TESTING.md](TESTING.md).

## Build notes

**macOS.** The scrypt NIF's Makefile assigns its Darwin link flags with `?=`, so an inherited `LDFLAGS` replaces rather than extends them and the NIF fails to link with undefined `_enif_*` symbols. If you export `LDFLAGS` globally (for example for `libpq`), either compile with `env -u LDFLAGS mix deps.compile scrypt` or append `-undefined dynamic_lookup` to your exported value.

**Native dependency.** scrypt is a NIF, so building needs a C compiler and `make`. The official `elixir:*` images carry both, and it builds on Debian for amd64 and arm64 alike.

## Attribution

A workalike of Apache-2.0 licensed work by Google LLC. See `NOTICE`.
