defmodule RecaptchaPasswordCheck.EcCommutativeCipher do
  @moduledoc """
  Commutative encryption over P-256, where `K₁(K₂(m)) == K₂(K₁(m))`.

  Two parties use this to learn whether they hold the same value without either revealing it.
  Encryption hashes the message onto the curve and multiplies by a private scalar; because scalar
  multiplication commutes, the server can re-encrypt a client ciphertext and the client can strip
  its own layer back off.

  See ["Using Commutative Encryption to Share a Secret"](https://eprint.iacr.org/2008/356.pdf).

  Ciphertexts are compressed curve points, 33 bytes each.
  """

  import Bitwise

  alias RecaptchaPasswordCheck.P256

  @hash_bit_lengths %{sha256: 256, sha384: 384, sha512: 512}

  @doc "A new random private key."
  def new_key, do: P256.random_scalar()

  @doc """
  Hashes `message` onto the curve, returning the compressed point.

  Derives a candidate x-coordinate from a random oracle over `message` and takes the positive
  root of `x³ + ax + b`; when that value is not a quadratic residue the x-coordinate is re-hashed
  and the search repeats.

  The root is normalised to the even y for every point, matching the reference implementation,
  which negates any root whose low bit is set.
  """
  def hash_into_the_curve(message, hash \\ :sha256) do
    message
    |> random_oracle(P256.p(), hash)
    |> find_point(hash)
    |> P256.compress()
  end

  @doc """
  Encrypts `message` under `key`: hashes onto the curve, then multiplies by the scalar.
  """
  def encrypt(key, message, hash \\ :sha256) do
    message
    |> random_oracle(P256.p(), hash)
    |> find_point(hash)
    |> P256.multiply(key)
    |> P256.compress()
  end

  @doc """
  Applies another layer of encryption to an existing ciphertext.

  Raises when `ciphertext` is not a valid point.
  """
  def re_encrypt(key, ciphertext) do
    ciphertext
    |> P256.decompress!()
    |> P256.multiply(key)
    |> P256.compress()
  end

  @doc """
  Removes this key's layer from `ciphertext` by multiplying by the scalar's inverse.

  Does not reverse the hash onto the curve, so the result is a point rather than the original
  message. Raises when `ciphertext` is not a valid point.
  """
  def decrypt(key, ciphertext) do
    ciphertext
    |> P256.decompress!()
    |> P256.multiply(P256.scalar_inverse(key))
    |> P256.compress()
  end

  @doc """
  Maps `message` deterministically into `[0, max_value)`.

  Expands the digest by hashing a one-byte counter prefixed to the message, concatenating
  successive digests, then reducing. The output is widened by an extra hash length before
  reduction to limit modulo bias.
  """
  def random_oracle(message, max_value, hash \\ :sha256) do
    hash_bits = Map.fetch!(@hash_bit_lengths, hash)
    output_bits = bit_length(max_value) + hash_bits
    iterations = div(output_bits + hash_bits - 1, hash_bits)
    excess_bits = iterations * hash_bits - output_bits

    1..iterations
    |> Enum.reduce(0, fn counter, acc ->
      digest = :crypto.hash(hash, :binary.encode_unsigned(counter) <> message)
      (acc <<< hash_bits) + :binary.decode_unsigned(digest)
    end)
    |> bsr(excess_bits)
    |> rem(max_value)
  end

  defp find_point(x, hash) do
    case P256.sqrt(P256.rhs(x)) do
      nil ->
        x
        |> :binary.encode_unsigned()
        |> random_oracle(P256.p(), hash)
        |> find_point(hash)

      root ->
        {x, if(rem(root, 2) == 1, do: P256.p() - root, else: root)}
    end
  end

  defp bit_length(0), do: 0
  defp bit_length(value) when value > 0, do: byte_size(Integer.to_string(value, 2))
end
