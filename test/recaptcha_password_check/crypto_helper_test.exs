defmodule RecaptchaPasswordCheck.CryptoHelperTest do
  use ExUnit.Case, async: true

  alias RecaptchaPasswordCheck.CryptoHelper

  doctest RecaptchaPasswordCheck.CryptoHelper

  defp hex(binary), do: Base.encode16(binary, case: :lower)

  # Expected values copied from Google's published test suites, which are ports
  # of google3 CryptoHelperTest.java. A mismatch here means this implementation
  # would query the wrong bucket or compare the wrong hash, and every credential
  # would silently come back clean.
  describe "hash_username/1" do
    test "matches the reference digest" do
      assert hex(CryptoHelper.hash_username("jonsnow")) ==
               "3d70d37bfc1a3d8145e6c7a3a4d7927661c1e8df82bd0c9f619aa3c996ec4cb3"
    end
  end

  describe "hash_username_password_pair/2" do
    test "matches the reference digest, pinning the scrypt parameters and salt" do
      assert hex(CryptoHelper.hash_username_password_pair("jonsnow", "Targaryen")) ==
               "f6e6fdb323af6f3d0310bb300e5a786b39a9a387c2eddecdfe184bf22330b272"
    end
  end

  describe "bucketize_username/2" do
    test "matches the reference bucket for the canary credential" do
      assert CryptoHelper.bucketize_username("leakedusername") == <<0xCE, 0x8C, 0x59, 0xC0>>
    end

    test "is a 26 bit prefix zero-filled to four bytes" do
      bucket = CryptoHelper.bucketize_username("jonsnow")

      assert byte_size(bucket) == 4
      <<_::26, tail::bitstring>> = bucket
      assert tail == <<0::6>>
    end
  end
end
