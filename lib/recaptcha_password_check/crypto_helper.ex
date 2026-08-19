defmodule RecaptchaPasswordCheck.CryptoHelper do
  @moduledoc false

  alias RecaptchaPasswordCheck.CryptoHelper.BitPrefix

  # These salts are public: They exist only to force an attacker to build a rainbow table
  # specific to this protocol rather than reusing a generic one.

  @username_salt <<0xC4, 0x94, 0xA3, 0x95, 0xF8, 0xC0, 0xE2, 0x3E, 0xA9, 0x23, 0x04, 0x78, 0x70,
                   0x2C, 0x72, 0x18, 0x56, 0x54, 0x99, 0xB3, 0xE9, 0x21, 0x18, 0x6C, 0x21, 0x1A,
                   0x01, 0x22, 0x3C, 0x45, 0x4A, 0xFA>>

  @password_salt <<0x30, 0x76, 0x2A, 0xD2, 0x3F, 0x7B, 0xA1, 0x9B, 0xF8, 0xE3, 0x42, 0xFC, 0xA1,
                   0xA7, 0x8D, 0x06, 0xE6, 0x6B, 0xE4, 0xDB, 0xB8, 0x4F, 0x81, 0x53, 0xC5, 0x03,
                   0xC8, 0xDB, 0xBD, 0xDE, 0xA5, 0x20>>

  @scrypt_cost 4096
  @scrypt_block_size 8
  @scrypt_parallelization 1
  @scrypt_key_length 32

  @username_hash_prefix_bits 26

  @doc false
  def username_hash_prefix_bits, do: @username_hash_prefix_bits

  @doc false
  # Hashes a canonicalized username.
  #
  # Deliberately fast: only a 26-bit prefix ever leaves the client, so this hash does not need to
  # resist offline attack.
  def hash_username(canonical_username) when is_binary(canonical_username) do
    :crypto.hash(:sha256, canonical_username <> @username_salt)
  end

  @doc false
  # Hashes a canonicalized username and password together with scrypt.
  #
  # Expensive by design — this value is the secret the protocol protects. Runs
  # scrypt with `N=4096, r=8, p=1` over the concatenated credentials, salted with
  # the username and a constant.
  def hash_username_password_pair(canonical_username, password)
      when is_binary(canonical_username) and is_binary(password) do
    :scrypt.scrypt(
      canonical_username <> password,
      canonical_username <> @password_salt,
      @scrypt_cost,
      @scrypt_block_size,
      @scrypt_parallelization,
      @scrypt_key_length
    )
  end

  @doc """
  The bucket identifier for a canonicalized username: the leading
  #{@username_hash_prefix_bits} bits of its hash, zero-filled to whole bytes.

      iex> RecaptchaPasswordCheck.CryptoHelper.bucketize_username("leakedusername")
      <<0xCE, 0x8C, 0x59, 0xC0>>
  """
  def bucketize_username(canonical_username, bits \\ @username_hash_prefix_bits) do
    canonical_username
    |> hash_username()
    |> BitPrefix.of(bits)
    |> BitPrefix.to_binary()
  end

  @doc false
  # Re-hashes an encrypted credentials hash, which the service also does to every leak it returns,
  # so both sides compare uniformly distributed values.
  def hash_blinded_hash(blinded_hash) when is_binary(blinded_hash) do
    :crypto.hash(:sha256, blinded_hash)
  end
end
