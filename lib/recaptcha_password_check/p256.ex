defmodule RecaptchaPasswordCheck.P256 do
  @moduledoc false
  # Arithmetic on the NIST P-256 (secp256r1) curve `y² = x³ + ax + b mod p`.
  #
  # Timing
  #
  # Scalar multiplication uses a Montgomery ladder, so the sequence of group operations does not
  # depend on the scalar's bits. It is *not* constant time in the strict sense: the BEAM's bignum
  # arithmetic is itself variable time. See the README for the threat model this is acceptable
  # under.

  # Parameters come from OTP's own curve table rather than being transcribed, so there is no
  # hand-typed constant to get wrong. Read at compile time so they stay usable in guards.
  {{:prime_field, field}, {coefficient_a, coefficient_b, _seed}, generator, group_order, cofactor} =
    :crypto.ec_curve(:secp256r1)

  <<4, generator_x::unsigned-big-integer-size(256), generator_y::unsigned-big-integer-size(256)>> =
    generator

  @p :binary.decode_unsigned(field)
  @a :binary.decode_unsigned(coefficient_a)
  @b :binary.decode_unsigned(coefficient_b)
  @n :binary.decode_unsigned(group_order)
  @gx generator_x
  @gy generator_y

  # `sqrt/1` takes the root as `v^((p+1)/4)`, which is only a root when `p ≡ 3 (mod 4)`. Fail the
  # build rather than silently compute wrong roots.
  if rem(@p, 4) != 3 do
    raise "#{inspect(__MODULE__)}.sqrt/1 assumes p ≡ 3 (mod 4), which this curve violates"
  end

  # Cofactor 1 means every point of the curve generates the whole group, so a point that satisfies
  # the curve equation cannot sit in a small subgroup. `decompress/1` therefore needs no
  # subgroup check beyond `on_curve?/1`.
  if :binary.decode_unsigned(cofactor) != 1 do
    raise "#{inspect(__MODULE__)} assumes a cofactor of 1"
  end

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

  def on_curve?({x, y})
      when is_integer(x) and is_integer(y) and x >= 0 and x < @p and y >= 0 and y < @p do
    rem(y * y - (x * x * x + @a * x + @b), @p) == 0
  end

  def on_curve?(_), do: false

  @doc "Modular inverse of `k` in the field, via Fermat's little theorem."
  def field_inverse(k) when is_integer(k) and k > 0, do: mod_pow(k, @p - 2, @p)

  @doc "Modular inverse of `k` modulo the group order."
  def scalar_inverse(k) when is_integer(k) and k > 0, do: mod_pow(k, @n - 2, @n)

  @doc """
  Modular square root of `v` in the field, or `nil` when `v` is not a quadratic residue.

  `p ≡ 3 (mod 4)`, so the candidate root is `v^((p+1)/4)`, verified by squaring.
  """
  def sqrt(v) when is_integer(v) do
    candidate = mod_pow(v, div(@p + 1, 4), @p)
    if rem(candidate * candidate, @p) == rem(v, @p), do: candidate
  end

  @doc "Right-hand side of the curve equation for `x`."
  def rhs(x) when is_integer(x), do: rem(x * x * x + @a * x + @b, @p)

  @doc "Point doubling."
  def double(:infinity), do: :infinity
  def double({_x, 0}), do: :infinity

  def double({x, y}) when is_integer(x) and is_integer(y) do
    # Tangent slope λ = (3x² + a) / 2y, then x₃ = λ² - 2x and y₃ = λ(x - x₃) - y.
    lambda = norm((3 * x * x + @a) * field_inverse(2 * y))
    xr = norm(lambda * lambda - 2 * x)
    yr = norm(lambda * (x - xr) - y)
    {xr, yr}
  end

  @doc "Point addition."
  def add(:infinity, q), do: q
  def add(p, :infinity), do: p

  def add({x1, y1}, {x2, y2})
      when is_integer(x1) and is_integer(y1) and is_integer(x2) and is_integer(y2) do
    cond do
      # Chord slope λ = (y₂ - y₁) / (x₂ - x₁), then x₃ = λ² - x₁ - x₂ and y₃ = λ(x₁ - x₃) - y₁.
      x1 != x2 ->
        lambda = norm((y2 - y1) * field_inverse(norm(x2 - x1)))
        xr = norm(lambda * lambda - x1 - x2)
        yr = norm(lambda * (x1 - xr) - y1)
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
  def multiply(_point, k) when is_integer(k) and k == 0, do: :infinity
  def multiply(:infinity, k) when is_integer(k), do: :infinity

  def multiply(point, k) when is_integer(k) do
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
