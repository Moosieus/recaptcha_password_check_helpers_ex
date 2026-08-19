defmodule RecaptchaPasswordCheck do
  @moduledoc """
  Client-side cryptography and canonicalization for Google Cloud Fraud Defense's private password leak check.
  """

  alias RecaptchaPasswordCheck.Verification

  @doc """
  Builds a `RecaptchaPasswordCheck.Verification` struct for a username and password.

  Runs scrypt and an elliptic curve multiplication, so expect low tens of milliseconds.

  > #### Google Cloud Fraud Defense uses canonicalized usernames. {: .warning}
  >
  > 1. Everything after the first `@` is trimmed.
  > 2. `.`'s are removed.
  > 3. Every ascii character is downcased.
  >
  > For example: `J.Doe@gmail.com` and `jdoe@hotmail.com` both equate to `jdoe` for leak checks.

  Returns `{:ok, verification}`, or `{:error, :empty_canonical_username}` when canonicalization
  consumes the username entirely — `"@example.com"` reduces to nothing, and a query on an empty
  username would match on the password alone.

  Raises when either credential is empty or not a binary, which is a caller error rather than a
  property of the input.
  """
  defdelegate create_verification(username, password), to: Verification, as: :create

  @doc """
  Unblinds the response fields using the `verification` and returns `true` if the credentials
  were found in a leak corpus.
  """
  defdelegate leaked?(verification, reencrypted_hash, match_prefixes), to: Verification
end
