defmodule RecaptchaPasswordCheck do
  @moduledoc """
  Client-side cryptography for reCAPTCHA's private password leak check.

  The service answers whether a username and password pair appears in a breach corpus without
  ever learning the credentials. This package does the client half of that exchange; sending the
  request is left to the caller.

  ## Usage

      verification = RecaptchaPasswordCheck.create_verification("user@example.com", "hunter2")

      # POST to projects.assessments.create with, base64-encoded:
      #   privatePasswordLeakVerification.lookupHashPrefix
      #     -> verification.lookup_hash_prefix
      #   privatePasswordLeakVerification.encryptedUserCredentialsHash
      #     -> verification.encrypted_user_credentials_hash

      result =
        RecaptchaPasswordCheck.verify(
          verification,
          response.reencrypted_user_credentials_hash,
          response.encrypted_leak_match_prefixes
        )

      result.leaked?
  """

  alias RecaptchaPasswordCheck.CryptoHelper
  alias RecaptchaPasswordCheck.Verification

  @doc """
  Builds a verification for a username and password.

  Runs scrypt and an elliptic curve multiplication, so expect low tens of milliseconds.

  Pass `private_key` only from tests to make the output deterministic.
  """
  def create_verification(username, password, private_key \\ nil) do
    Verification.create(username, password, private_key)
  end

  @doc """
  Interprets the service's response against the verification that produced it.

  Returns a `RecaptchaPasswordCheck.Result`.
  """
  defdelegate verify(verification, reencrypted_hash, match_prefixes), to: Verification

  @doc """
  Canonicalizes a username the way the protocol does.

  Exposed because the transformation is lossy in a way worth being aware of: the email host is
  discarded, so `alice@example.com` and `alice@other.test` collide. A reported leak means the
  local part and password appeared together, not that this exact account was breached.
  """
  defdelegate canonicalize_username(username), to: CryptoHelper
end
