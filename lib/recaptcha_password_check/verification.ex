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

  @doc """
  Builds a verification for `username` and `password`.

  Generates a fresh private key unless one is supplied, which callers should do only in tests —
  reusing a key across verifications makes the deterministic encryption linkable.

  Raises `ArgumentError` when either credential is empty.
  """
  def create(username, password, private_key \\ nil)

  def create(username, _password, _private_key) when username in [nil, ""] do
    raise ArgumentError, "Username cannot be null or empty"
  end

  def create(_username, password, _private_key) when password in [nil, ""] do
    raise ArgumentError, "Password cannot be null or empty"
  end

  def create(username, password, private_key) do
    canonical_username = CryptoHelper.canonicalize_username(username)
    private_key = private_key || EcCommutativeCipher.new_key()

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

  Raises `ArgumentError` on an empty `reencrypted_hash`.
  """
  def verify(%__MODULE__{} = verification, reencrypted_hash, match_prefixes)
      when is_list(match_prefixes) do
    if reencrypted_hash in [nil, ""] do
      raise ArgumentError, "reencrypted_hash must be present"
    end

    rehashed =
      verification.private_key
      |> EcCommutativeCipher.decrypt(reencrypted_hash)
      |> CryptoHelper.hash_blinded_hash()

    %Result{
      username: verification.username,
      leaked?: Enum.any?(match_prefixes, &prefix_match?(rehashed, &1))
    }
  end

  defp prefix_match?(_rehashed, prefix) when prefix in [nil, ""], do: false

  defp prefix_match?(rehashed, prefix) when byte_size(prefix) <= byte_size(rehashed) do
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
