defmodule RecaptchaPasswordCheck.P256 do
  @moduledoc """
  Arithmetic on the NIST P-256 (secp256r1) curve `y² = x³ + ax + b mod p`.

  Erlang's `:crypto` exposes no scalar multiplication of an arbitrary point — ECDH
  returns only the shared x-coordinate, and this protocol needs full compressed
  points — so the group law is implemented here. Field inversion and square roots
  delegate to `:crypto.mod_pow/3`.

  Points are `{x, y}` tuples in affine coordinates, or `:infinity`.

  > #### Timing {: .warning}
  >
  > Scalar multiplication uses a Montgomery ladder, so the sequence of group
  > operations does not depend on the scalar's bits. It is *not* constant time in
  > the strict sense: the BEAM's bignum arithmetic is itself variable time. See
  > the README for the threat model this is acceptable under.
  """

  @p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @a 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
  @b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
  @gx 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
  @gy 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
  @n 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

  @doc "Field characteristic."
  def p, do: @p

  @doc "Order of the base point."
  def n, do: @n

  @doc "Base point."
  def generator, do: {@gx, @gy}

  @doc "Curve coefficient `a`, equal to `p - 3`."
  def a, do: @a

  @doc "Curve coefficient `b`."
  def b, do: @b

  @doc "Whether `point` satisfies the curve equation. `:infinity` is not considered on the curve."
  def on_curve?(:infinity), do: false

  def on_curve?({x, y}) when x >= 0 and x < @p and y >= 0 and y < @p do
    rem(y * y - (x * x * x + @a * x + @b), @p) == 0
  end

  def on_curve?(_), do: false

  @doc "Modular inverse of `k` in the field, via Fermat's little theorem."
  def field_inverse(k) when k > 0, do: mod_pow(k, @p - 2, @p)

  @doc "Modular inverse of `k` modulo the group order."
  def scalar_inverse(k) when k > 0, do: mod_pow(k, @n - 2, @n)

  @doc """
  Modular square root of `v` in the field, or `nil` when `v` is not a quadratic residue.

  `p ≡ 3 (mod 4)`, so the candidate root is `v^((p+1)/4)`, verified by squaring.
  """
  def sqrt(v) do
    candidate = mod_pow(v, div(@p + 1, 4), @p)
    if rem(candidate * candidate, @p) == rem(v, @p), do: candidate
  end

  @doc "Right-hand side of the curve equation for `x`."
  def rhs(x), do: rem(x * x * x + @a * x + @b, @p)

  @doc "Point doubling."
  def double(:infinity), do: :infinity
  def double({_x, 0}), do: :infinity

  def double({x, y}) do
    lambda = rem((3 * x * x + @a) * field_inverse(2 * y), @p)
    xr = rem(lambda * lambda - 2 * x, @p) |> norm()
    yr = rem(lambda * (x - xr) - y, @p) |> norm()
    {xr, yr}
  end

  @doc "Point addition."
  def add(:infinity, q), do: q
  def add(p, :infinity), do: p

  def add({x1, y1}, {x2, y2}) do
    cond do
      x1 != x2 ->
        lambda = norm((y2 - y1) * field_inverse(norm(x2 - x1)))
        xr = rem(lambda * lambda - x1 - x2, @p) |> norm()
        yr = rem(lambda * (x1 - xr) - y1, @p) |> norm()
        {xr, yr}

      y1 == y2 ->
        double({x1, y1})

      true ->
        :infinity
    end
  end

  @doc """
  Scalar multiplication `k * point` via a Montgomery ladder.

  The scalar is reduced modulo the group order first; a scalar congruent to zero
  yields `:infinity`.
  """
  def multiply(_point, k) when k == 0, do: :infinity
  def multiply(:infinity, _k), do: :infinity

  def multiply(point, k) do
    k = rem(k, @n)

    if k == 0 do
      :infinity
    else
      k
      |> Integer.to_string(2)
      |> String.to_charlist()
      |> Enum.reduce({:infinity, point}, fn
        ?0, {r0, r1} -> {double(r0), add(r0, r1)}
        ?1, {r0, r1} -> {add(r0, r1), double(r1)}
      end)
      |> elem(0)
    end
  end

  @doc """
  Encodes a point in compressed form per ANSI X9.62: a parity byte followed by
  the 32-byte big-endian x-coordinate.
  """
  def compress({x, y}), do: <<2 + rem(y, 2)::8, x::unsigned-big-integer-size(256)>>

  @doc """
  Decodes a compressed point, verifying it lies on the curve and is not the
  point at infinity.

  Returns `{:ok, point}` or `{:error, reason}`.
  """
  def decompress(<<parity::8, x::unsigned-big-integer-size(256)>>) when parity in [2, 3] do
    with true <- x < @p,
         root when is_integer(root) <- sqrt(rhs(x)) do
      y = if rem(root, 2) == parity - 2, do: root, else: norm(-root)
      point = {x, y}

      if on_curve?(point), do: {:ok, point}, else: {:error, :not_on_curve}
    else
      _ -> {:error, :not_on_curve}
    end
  end

  def decompress(_), do: {:error, :invalid_encoding}

  @doc "Same as `decompress/1` but raises on invalid input."
  def decompress!(binary) do
    case decompress(binary) do
      {:ok, point} -> point
      {:error, reason} -> raise ArgumentError, "invalid compressed point: #{reason}"
    end
  end

  @doc "A uniformly random scalar in `[1, n-1]`, suitable as a private key."
  def random_scalar do
    <<candidate::unsigned-big-integer-size(256)>> = :crypto.strong_rand_bytes(32)

    if candidate >= 1 and candidate < @n, do: candidate, else: random_scalar()
  end

  defp norm(v), do: v |> rem(@p) |> then(&if(&1 < 0, do: &1 + @p, else: &1))

  defp mod_pow(base, exponent, modulus) do
    base
    |> :crypto.mod_pow(exponent, modulus)
    |> :binary.decode_unsigned()
  end
end
