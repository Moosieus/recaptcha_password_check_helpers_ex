defmodule RecaptchaPasswordCheck.Verification do
  @moduledoc """
  A single password check attempt.
  """

  alias RecaptchaPasswordCheck.CryptoHelper
  alias RecaptchaPasswordCheck.EcCommutativeCipher
  alias RecaptchaPasswordCheck.Result

  @enforce_keys [
    :username,
    :canonical_username,
    :lookup_hash_prefix,
    :encrypted_user_credentials_hash,
    :private_key
  ]

  defstruct @enforce_keys

  defguardp is_str(str) when is_binary(str) and byte_size(str) > 0

  @doc """
  Builds a verification for `username` and `password`.

  Generates a fresh private key on every call, and offers no way to supply one. The encryption is
  deterministic, so a reused key would make two verifications of the same credentials linkable.
  """
  def create(username, password) when is_str(username) and is_str(password) do
    canonical_username = CryptoHelper.canonicalize_username(username)
    private_key = EcCommutativeCipher.new_key()

    credentials_hash = CryptoHelper.hash_username_password_pair(canonical_username, password)

    %__MODULE__{
      username: username,
      canonical_username: canonical_username,
      lookup_hash_prefix: CryptoHelper.bucketize_username(canonical_username),
      encrypted_user_credentials_hash: EcCommutativeCipher.encrypt(private_key, credentials_hash),
      private_key: private_key
    }
  end

  @doc """
  Interprets a service response.

  Strips this verification's encryption layer from `reencrypted_hash`, re-hashes the result the
  way the service hashes every leak it stores, and reports whether any entry in `match_prefixes`
  prefixes that value.
  """
  def verify(%__MODULE__{} = verification, reencrypted_hash, [])
      when is_str(reencrypted_hash) do
    %Result{username: verification.username, leaked?: false}
  end

  def verify(%__MODULE__{} = verification, reencrypted_hash, [_ | _] = match_prefixes)
      when is_str(reencrypted_hash) do
    rehashed =
      verification.private_key
      |> EcCommutativeCipher.decrypt(reencrypted_hash)
      |> CryptoHelper.hash_blinded_hash()

    %Result{
      username: verification.username,
      leaked?: Enum.any?(match_prefixes, &prefix_match?(rehashed, &1))
    }
  end

  defp prefix_match?(rehashed, prefix)
       when is_str(rehashed) and is_str(prefix) and byte_size(prefix) <= byte_size(rehashed) do
    :crypto.hash_equals(binary_part(rehashed, 0, byte_size(prefix)), prefix)
  end

  defp prefix_match?(_rehashed, _prefix), do: false

  defimpl Inspect do
    import Inspect.Algebra

    def inspect(verification, opts) do
      redacted = %{
        username: verification.username,
        canonical_username: verification.canonical_username,
        lookup_hash_prefix: verification.lookup_hash_prefix,
        encrypted_user_credentials_hash: verification.encrypted_user_credentials_hash,
        private_key: "[REDACTED]"
      }

      concat(["#RecaptchaPasswordCheck.Verification<", to_doc(redacted, opts), ">"])
    end
  end
end
