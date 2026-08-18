defmodule RecaptchaPasswordCheck.VerificationTest do
  use ExUnit.Case, async: true

  alias RecaptchaPasswordCheck.CryptoHelper
  alias RecaptchaPasswordCheck.EcCommutativeCipher, as: Cipher
  alias RecaptchaPasswordCheck.Verification

  @moduledoc """
  Exercises the full request/response cycle against a locally simulated service.

  The simulation is faithful because the client half of the protocol pins the
  server's behaviour: the service can only re-encrypt the blinded hash under its
  own key and return SHA-256 prefixes of the leaks in the bucket. Reproducing
  that needs no network and no credentials, so the leaked and not-leaked paths
  are both covered by the ordinary suite.
  """

  # Mirrors the reference test harness, including the 20 byte truncation the
  # service applies to the prefixes it returns.
  defmodule FakeService do
    def respond(verification, leaked_credentials) do
      server_key = Cipher.new_key()

      reencrypted =
        Cipher.re_encrypt(server_key, verification.encrypted_user_credentials_hash)

      prefixes =
        Enum.map(leaked_credentials, fn {username, password} ->
          username
          |> CryptoHelper.canonicalize_username()
          |> CryptoHelper.hash_username_password_pair(password)
          |> then(&Cipher.encrypt(server_key, &1))
          |> CryptoHelper.hash_blinded_hash()
          |> binary_part(0, 20)
        end)

      {reencrypted, prefixes}
    end
  end

  describe "create/3" do
    test "populates both request fields" do
      verification = Verification.create("foo", "bar")

      assert byte_size(verification.lookup_hash_prefix) == 4
      assert byte_size(verification.encrypted_user_credentials_hash) == 33
      assert verification.username == "foo"
    end

    test "keeps the original username but canonicalizes for hashing" do
      verification = Verification.create("Foo.Bar@example.com", "pw")

      assert verification.username == "Foo.Bar@example.com"
      assert verification.canonical_username == "foobar"
    end

    test "generates a distinct key per verification" do
      refute Verification.create("foo", "bar").private_key ==
               Verification.create("foo", "bar").private_key
    end

    test "rejects an empty username" do
      assert_raise FunctionClauseError, fn -> Verification.create("", "bar") end
    end

    test "rejects an empty password" do
      assert_raise FunctionClauseError, fn -> Verification.create("foo", "") end
    end

    test "redacts the private key when inspected" do
      inspected = inspect(Verification.create("foo", "bar"))

      assert inspected =~ "[REDACTED]"
      refute inspected =~ to_string(Verification.create("foo", "bar").private_key)
    end
  end

  describe "verify/3" do
    test "reports a leak when the bucket contains the credentials" do
      verification = Verification.create("foo", "bar")

      {reencrypted, prefixes} =
        FakeService.respond(verification, [{"foo", "bar"}, {"baz", "pass"}])

      assert Verification.verify(verification, reencrypted, prefixes).leaked?
    end

    test "reports no leak when the password differs" do
      verification = Verification.create("foo", "bar")

      {reencrypted, prefixes} =
        FakeService.respond(verification, [{"foo", "diff_password"}, {"baz", "pass"}])

      refute Verification.verify(verification, reencrypted, prefixes).leaked?
    end

    test "reports no leak for an empty bucket" do
      verification = Verification.create("foo", "bar")
      {reencrypted, []} = FakeService.respond(verification, [])

      refute Verification.verify(verification, reencrypted, []).leaked?
    end

    # Proof the short-circuit is live: an empty bucket is already the answer, so the reencrypted
    # hash is never decrypted and never has to be a valid point.
    test "an empty bucket answers without touching the reencrypted hash" do
      verification = Verification.create("foo", "bar")

      refute Verification.verify(verification, "not a valid curve point", []).leaked?
    end

    test "returns the username alongside the verdict" do
      verification = Verification.create("foo", "bar")
      {reencrypted, prefixes} = FakeService.respond(verification, [{"foo", "bar"}])

      assert Verification.verify(verification, reencrypted, prefixes).username == "foo"
    end

    test "ignores empty prefixes" do
      verification = Verification.create("foo", "bar")
      {reencrypted, _} = FakeService.respond(verification, [])

      refute Verification.verify(verification, reencrypted, [""]).leaked?
    end

    test "ignores a prefix longer than the hash it would match against" do
      verification = Verification.create("foo", "bar")
      {reencrypted, _} = FakeService.respond(verification, [])

      refute Verification.verify(verification, reencrypted, [:crypto.strong_rand_bytes(33)]).leaked?
    end

    test "a canonicalizing username still matches the canonical leak entry" do
      verification = Verification.create("Foo.Bar@example.com", "bar")
      {reencrypted, prefixes} = FakeService.respond(verification, [{"foobar", "bar"}])

      assert Verification.verify(verification, reencrypted, prefixes).leaked?
    end

    test "another verification's key cannot read the response" do
      verification = Verification.create("foo", "bar")
      {reencrypted, prefixes} = FakeService.respond(verification, [{"foo", "bar"}])
      other = Verification.create("foo", "bar")

      refute Verification.verify(other, reencrypted, prefixes).leaked?
    end

    test "rejects an empty reencrypted hash" do
      verification = Verification.create("foo", "bar")

      assert_raise FunctionClauseError, fn -> Verification.verify(verification, "", [<<1>>]) end
    end
  end
end
