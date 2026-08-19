defmodule RecaptchaPasswordCheck.CryptoHelper.BitPrefixTest do
  use ExUnit.Case, async: true

  alias RecaptchaPasswordCheck.CryptoHelper.BitPrefix

  doctest RecaptchaPasswordCheck.CryptoHelper.BitPrefix

  # Expected values copied from Google's published test suites, which are
  # themselves ports of google3 BitPrefixTest.java.
  describe "of/2" do
    test "handles multiple bytes" do
      prefix = BitPrefix.of(<<0b11111111, 0b01010101>>, 9)

      assert prefix.bits == 9
      assert to_string(prefix) == "0b111111110"
    end

    test "handles a byte boundary" do
      prefix = BitPrefix.of(<<0b11111111, 0b01010101>>, 8)

      assert prefix.bits == 8
      assert to_string(prefix) == "0b11111111"
    end

    test "handles leading zeros" do
      prefix = BitPrefix.of(<<0b00000000, 0b01010101>>, 9)

      assert prefix.bits == 9
      assert to_string(prefix) == "0b000000000"
    end

    test "handles leading zeros when the binary is one byte" do
      prefix = BitPrefix.of(<<0b00000010>>, 7)

      assert prefix.bits == 7
      assert to_string(prefix) == "0b0000001"
    end

    test "handles a single bit prefix" do
      prefix = BitPrefix.of(<<0b11111111>>, 1)

      assert prefix.bits == 1
      assert to_string(prefix) == "0b1"
    end

    test "raises on an empty binary" do
      assert_raise ArgumentError, fn -> BitPrefix.of(<<>>, 1) end
    end

    test "raises when asked for more bits than are available" do
      assert_raise ArgumentError, fn -> BitPrefix.of(<<0xFF>>, 9) end
    end

    test "renders an empty prefix" do
      assert to_string(BitPrefix.of(<<0xFF>>, 0)) == "Empty prefix"
    end
  end

  describe "to_binary/1" do
    test "zero-fills the trailing bits of the last byte" do
      assert <<0xCE, 0x8C, 0x59, 0xDF>>
             |> BitPrefix.of(26)
             |> BitPrefix.to_binary() == <<0xCE, 0x8C, 0x59, 0xC0>>
    end

    test "zero-fills a short prefix" do
      assert <<0xCE, 0x8C, 0x59, 0xDF>>
             |> BitPrefix.of(12)
             |> BitPrefix.to_binary() == <<0xCE, 0x80>>
    end
  end
end
