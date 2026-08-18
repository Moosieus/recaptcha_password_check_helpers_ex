defmodule RecaptchaPasswordCheck.P256Test do
  use ExUnit.Case, async: true

  alias RecaptchaPasswordCheck.P256

  # The curve arithmetic has no reference vectors of its own, but it does not need
  # any: OTP ships a P-256 implementation, and ECDH exercises exactly the
  # operation implemented here. `generate_key/3` gives `k * G`, and
  # `compute_key/4` gives the x-coordinate of `k * P` for an arbitrary `P`.
  defp priv(k), do: <<k::unsigned-big-integer-size(256)>>

  defp uncompressed_to_point(
         <<4, x::unsigned-big-integer-size(256), y::unsigned-big-integer-size(256)>>
       ),
       do: {x, y}

  describe "multiply/2 against :crypto" do
    test "matches OTP for scalar multiplication of the generator" do
      for _ <- 1..20 do
        k = P256.random_scalar()
        {public, _private} = :crypto.generate_key(:ecdh, :secp256r1, priv(k))

        assert P256.multiply(P256.generator(), k) == uncompressed_to_point(public)
      end
    end

    test "matches OTP ECDH for scalar multiplication of an arbitrary point" do
      for _ <- 1..20 do
        peer_scalar = P256.random_scalar()
        {peer_public, _} = :crypto.generate_key(:ecdh, :secp256r1, priv(peer_scalar))
        peer_point = uncompressed_to_point(peer_public)

        k = P256.random_scalar()
        shared = :crypto.compute_key(:ecdh, peer_public, priv(k), :secp256r1)
        {x, _y} = P256.multiply(peer_point, k)

        assert <<x::unsigned-big-integer-size(256)>> == shared
      end
    end
  end

  describe "group law" do
    test "n * G is the point at infinity" do
      assert P256.multiply(P256.generator(), P256.n()) == :infinity
    end

    test "a scalar and its inverse cancel" do
      point = P256.multiply(P256.generator(), P256.random_scalar())
      k = P256.random_scalar()

      assert point
             |> P256.multiply(k)
             |> P256.multiply(P256.scalar_inverse(k)) == point
    end

    test "addition is commutative" do
      a = P256.multiply(P256.generator(), P256.random_scalar())
      b = P256.multiply(P256.generator(), P256.random_scalar())

      assert P256.add(a, b) == P256.add(b, a)
    end

    test "adding a point to its own negation yields infinity" do
      {x, y} = P256.multiply(P256.generator(), P256.random_scalar())

      assert P256.add({x, y}, {x, P256.p() - y}) == :infinity
    end

    test "doubling agrees with adding a point to itself" do
      point = P256.multiply(P256.generator(), P256.random_scalar())

      assert P256.double(point) == P256.add(point, point)
    end

    test "infinity is the identity" do
      point = P256.multiply(P256.generator(), P256.random_scalar())

      assert P256.add(point, :infinity) == point
      assert P256.add(:infinity, point) == point
      assert P256.double(:infinity) == :infinity
    end
  end

  describe "on_curve?/1" do
    test "accepts generated points" do
      for _ <- 1..20 do
        assert P256.on_curve?(P256.multiply(P256.generator(), P256.random_scalar()))
      end
    end

    test "rejects a point off the curve" do
      {x, y} = P256.generator()

      refute P256.on_curve?({x, y + 1})
    end

    test "rejects infinity and malformed input" do
      refute P256.on_curve?(:infinity)
      refute P256.on_curve?({-1, 0})
      refute P256.on_curve?({P256.p(), 0})
    end
  end

  describe "compress/1 and decompress/1" do
    test "round trip preserves the point" do
      for _ <- 1..20 do
        point = P256.multiply(P256.generator(), P256.random_scalar())

        assert {:ok, ^point} = point |> P256.compress() |> P256.decompress()
      end
    end

    test "encodes to 33 bytes with a parity prefix" do
      point = P256.multiply(P256.generator(), P256.random_scalar())
      <<prefix::8, _rest::binary>> = compressed = P256.compress(point)

      assert byte_size(compressed) == 33
      assert prefix in [2, 3]
    end

    test "rejects an x-coordinate with no corresponding y" do
      x = Enum.find(1..1000, fn x -> P256.sqrt(P256.rhs(x)) == nil end)

      assert {:error, :not_on_curve} =
               P256.decompress(<<2, x::unsigned-big-integer-size(256)>>)
    end

    test "rejects an out-of-range x-coordinate" do
      assert {:error, :not_on_curve} =
               P256.decompress(<<2, P256.p()::unsigned-big-integer-size(256)>>)
    end

    test "rejects bad encodings" do
      assert {:error, :invalid_encoding} = P256.decompress(<<>>)
      assert {:error, :invalid_encoding} = P256.decompress(<<4, 0::512>>)
      assert {:error, :invalid_encoding} = P256.decompress(<<2, 0::128>>)
    end

    test "decompress!/1 raises on invalid input" do
      assert_raise ArgumentError, fn -> P256.decompress!(<<>>) end
    end
  end

  describe "sqrt/1" do
    test "returns a root when one exists" do
      {x, _y} = P256.multiply(P256.generator(), P256.random_scalar())
      root = P256.sqrt(P256.rhs(x))

      assert is_integer(root)
      assert rem(root * root, P256.p()) == P256.rhs(x)
    end

    test "returns nil for a non-residue" do
      non_residue = Enum.find(1..1000, fn v -> P256.sqrt(v) == nil end)

      assert is_integer(non_residue)
    end
  end
end
