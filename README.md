# RecaptchaPasswordCheck

An Elixir workalike of Google's [`java-recaptcha-password-check-helpers`](https://github.com/GoogleCloudPlatform/java-recaptcha-password-check-helpers), the client-side cryptography for reCAPTCHA's [private password leak
check](https://docs.cloud.google.com/recaptcha/docs/check-passwords).

## Installation

```elixir
def deps do
  [{:recaptcha_password_check, "~> 0.1.0"}]
end
```

Documentation is available on [HexDocs](https://recaptcha-password-check.hexdocs.pm/readme.html) and may also be generated with [ExDoc](https://github.com/elixir-lang/ex_doc).

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

# Short of adopting `:protobuf` to restore proto3's presence semantics,
# the response shapes have to be spelled out by hand.
case response do
  %{
    status: 200,
    body: %{
      "privatePasswordLeakVerification" => %{
        "reencryptedUserCredentialsHash" => reencrypted_user_credentials_hash,
        "encryptedLeakMatchPrefixes" => encrypted_leak_match_prefixes
      }
    }
  } ->
    RecaptchaPasswordCheck.leaked?(
      verification,
      Base.decode64!(reencrypted_user_credentials_hash),
      Enum.map(encrypted_leak_match_prefixes, &Base.decode64!/1)
    )

  %{status: 200, body: %{"privatePasswordLeakVerification" => _}} ->
    false

  %{status: status, body: body} ->
    {:error, {status, body}}
end
```

Get the token from `:goth` in an application or from `gcloud auth print-access-token` when trying this out by hand.

<!-- MDOC !-->

## Testing

See [TESTING.md](TESTING.md).

## Building

The `scrypt` NIF needs a C compiler and `make`. On macOS an exported `LDFLAGS` clobbers the link flags it needs, which may require using `env -u LDFLAGS mix compile`.

## Attribution

A workalike of Apache-2.0 licensed work by Google LLC. See `NOTICE`.
