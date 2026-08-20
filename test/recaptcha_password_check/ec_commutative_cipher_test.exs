defmodule RecaptchaPasswordCheck.EcCommutativeCipherTest do
  use ExUnit.Case, async: true

  alias RecaptchaPasswordCheck.EcCommutativeCipher, as: Cipher
  alias RecaptchaPasswordCheck.EcCommutativeCipher.P256

  describe "hash_into_the_curve/2" do
    test "produces a valid compressed point" do
      assert {:ok, point} = "hello" |> Cipher.hash_into_the_curve() |> P256.decompress()
      assert P256.on_curve?(point)
    end

    test "is deterministic" do
      assert Cipher.hash_into_the_curve("hello") == Cipher.hash_into_the_curve("hello")
    end

    test "separates distinct messages" do
      refute Cipher.hash_into_the_curve("hello") == Cipher.hash_into_the_curve("hellp")
    end

    test "always normalises to an even y" do
      for i <- 1..50 do
        <<parity::8, _::binary>> = Cipher.hash_into_the_curve("message #{i}")

        assert parity == 2
      end
    end

    # Roughly half of candidate x-coordinates are not on the curve, so a sample
    # this size exercises the re-hash path many times over. It asserts only that
    # the result is self-consistent; byte-level agreement with the reference retry
    # encoding comes from the parity fixtures, whose inputs include usernames that
    # retry.
    test "handles the re-hash path across many inputs" do
      for i <- 1..100 do
        assert {:ok, point} =
                 "retry #{i}" |> Cipher.hash_into_the_curve() |> P256.decompress()

        assert P256.on_curve?(point)
      end
    end
  end

  describe "random_oracle/3" do
    test "matches the two-digest construction for a 256 bit modulus" do
      message = "some message"

      <<expected::unsigned-big-integer-size(512)>> =
        :crypto.hash(:sha256, <<1>> <> message) <> :crypto.hash(:sha256, <<2>> <> message)

      assert Cipher.random_oracle(message, P256.p()) == rem(expected, P256.p())
    end

    test "stays within range" do
      for i <- 1..50 do
        value = Cipher.random_oracle("m#{i}", 1000)

        assert value >= 0 and value < 1000
      end
    end
  end

  describe "commutativity" do
    test "encrypting under two keys is order independent" do
      k1 = Cipher.new_key()
      k2 = Cipher.new_key()
      message = "credentials hash"

      assert Cipher.re_encrypt(k2, Cipher.encrypt(k1, message)) ==
               Cipher.re_encrypt(k1, Cipher.encrypt(k2, message))
    end

    test "decrypting strips one layer and leaves the other" do
      client = Cipher.new_key()
      server = Cipher.new_key()
      message = "credentials hash"

      # This is the whole protocol: the client blinds, the server re-encrypts,
      # the client unblinds, and what remains is what the server would have
      # computed on its own.
      round_tripped =
        client
        |> Cipher.encrypt(message)
        |> then(&Cipher.re_encrypt(server, &1))
        |> then(&Cipher.decrypt(client, &1))

      assert round_tripped == Cipher.encrypt(server, message)
    end

    test "a different key yields a different ciphertext" do
      message = "credentials hash"

      refute Cipher.encrypt(Cipher.new_key(), message) ==
               Cipher.encrypt(Cipher.new_key(), message)
    end

    test "encryption is deterministic for a fixed key" do
      key = Cipher.new_key()

      assert Cipher.encrypt(key, "m") == Cipher.encrypt(key, "m")
    end
  end

  describe "input validation" do
    test "re_encrypt/2 rejects a point that is not on the curve" do
      x = Enum.find(1..1000, fn x -> P256.sqrt(P256.rhs(x)) == nil end)

      assert_raise ArgumentError, fn ->
        Cipher.re_encrypt(Cipher.new_key(), <<2, x::unsigned-big-integer-size(256)>>)
      end
    end

    test "decrypt/2 rejects a malformed ciphertext" do
      assert_raise ArgumentError, fn -> Cipher.decrypt(Cipher.new_key(), <<0, 1, 2>>) end
    end
  end
end
