defmodule RecaptchaPasswordCheck.Verification do
  @moduledoc """
  A single password check attempt, carrying everything needed to make one request and read its reply.
  """

  alias RecaptchaPasswordCheck.CryptoHelper
  alias RecaptchaPasswordCheck.EcCommutativeCipher

  @doc """
  Defines the RecaptchaPasswordCheck.Verification struct.

  Its fields are:

    * `:username` - the username as it was supplied.
    * `:canonical_username` - that username after canonicalization, which is what every hash here
      derives from.
    * `:lookup_hash_prefix` - four bytes holding the leading 26 bits of the canonical username's
      hash, zero-filled. It names the bucket of leaks the service searches, and is the only thing
      the service learns about the username.
    * `:encrypted_user_credentials_hash` - the scrypt hash of the canonical username and password,
      blinded by multiplication on P-256 and encoded as a 33-byte compressed point. The service
      re-encrypts it under its own key without being able to read it.
    * `:private_key` - the ephemeral scalar used for that blinding, and the only means of removing
      it from the reply. Never reused, never transmitted, and redacted when the struct is inspected.
  """
  defstruct [
    :username,
    :canonical_username,
    :lookup_hash_prefix,
    :encrypted_user_credentials_hash,
    :private_key
  ]

  defguardp is_str(str) when is_binary(str) and byte_size(str) > 0

  @doc false
  def create(username, password) when is_str(username) and is_str(password) do
    case canonicalize_username(username) do
      canonical when canonical != "" -> {:ok, build(username, canonical, password)}
      "" -> {:error, :empty_canonical_username}
    end
  end

  defp build(username, canonical_username, password) do
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

  @doc false
  # Applies reCAPTCHA's canonicalization rules, matching the reference implementation byte for byte.
  def canonicalize_username(username) when is_binary(username) do
    username
    |> strip_host()
    |> String.replace(".", "")
    |> ascii_downcase()
  end

  defp strip_host(username) do
    case :binary.match(username, "@") do
      {index, _length} -> :binary.part(username, 0, index)
      :nomatch -> username
    end
  end

  defp ascii_downcase(binary) do
    for <<byte <- binary>>, into: "", do: <<downcase_byte(byte)>>
  end

  defp downcase_byte(byte) when byte in ?A..?Z, do: byte + 32
  defp downcase_byte(byte), do: byte

  @doc false
  def leaked?(%__MODULE__{} = verification, reencrypted_hash, [_ | _] = match_prefixes)
      when is_str(reencrypted_hash) do
    rehashed =
      verification.private_key
      |> EcCommutativeCipher.decrypt(reencrypted_hash)
      |> CryptoHelper.hash_blinded_hash()

    Enum.any?(match_prefixes, &prefix_match?(rehashed, &1))
  end

  def leaked?(%__MODULE__{}, reencrypted_hash, []) when is_str(reencrypted_hash) do
    false
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
