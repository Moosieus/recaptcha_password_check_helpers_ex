defmodule RecaptchaPasswordCheckTest do
  use ExUnit.Case, async: true

  alias RecaptchaPasswordCheck.Verification

  describe "create_verification/2" do
    # The facade is thin, but thin is not free: a wrong delegation target or a self-call would hang
    # or crash every caller while every unit test below still passed.
    test "returns a populated verification" do
      assert {:ok, verification} =
               RecaptchaPasswordCheck.create_verification("Foo.Bar@example.com", "pw")

      assert %Verification{} = verification
      assert verification.username == "Foo.Bar@example.com"
      assert verification.canonical_username == "foobar"
      assert byte_size(verification.lookup_hash_prefix) == 4
      assert byte_size(verification.encrypted_user_credentials_hash) == 33
    end

    # Google's own library would hash the empty username, but an empty query matches on the
    # password alone, so this refuses rather than asking.
    test "reports a username that canonicalizes to nothing" do
      assert RecaptchaPasswordCheck.create_verification("@nolocalpart", "pw") ==
               {:error, :empty_canonical_username}
    end

    test "rejects raw credentials that are empty or not binaries" do
      assert_raise FunctionClauseError, fn ->
        RecaptchaPasswordCheck.create_verification("", "pw")
      end

      assert_raise FunctionClauseError, fn ->
        RecaptchaPasswordCheck.create_verification("user", "")
      end
    end
  end
end
