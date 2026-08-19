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
          |> Verification.canonicalize_username()
          |> CryptoHelper.hash_username_password_pair(password)
          |> then(&Cipher.encrypt(server_key, &1))
          |> CryptoHelper.hash_blinded_hash()
          |> binary_part(0, 20)
        end)

      {reencrypted, prefixes}
    end
  end

  defp create!(username, password) do
    {:ok, verification} = Verification.create(username, password)

    verification
  end

  describe "create/3" do
    test "populates both request fields" do
      verification = create!("foo", "bar")

      assert byte_size(verification.lookup_hash_prefix) == 4
      assert byte_size(verification.encrypted_user_credentials_hash) == 33
      assert verification.username == "foo"
    end

    # Both forms are retained: the address as entered, and the one everything is hashed from.
    test "keeps the username as entered and canonicalizes for hashing" do
      verification = create!("Foo.Bar@example.com", "pw")

      assert verification.username == "Foo.Bar@example.com"
      assert verification.canonical_username == "foobar"

      assert verification.lookup_hash_prefix == CryptoHelper.bucketize_username("foobar")
    end

    test "reports a username that canonicalizes to nothing" do
      assert Verification.create("@nolocalpart", "pw") == {:error, :empty_canonical_username}
    end

    test "generates a distinct key per verification" do
      refute create!("foo", "bar").private_key ==
               create!("foo", "bar").private_key
    end

    test "rejects an empty username" do
      assert_raise FunctionClauseError, fn -> Verification.create("", "bar") end
    end

    test "rejects an empty password" do
      assert_raise FunctionClauseError, fn -> Verification.create("foo", "") end
    end

    test "redacts the private key when inspected" do
      inspected = inspect(create!("foo", "bar"))

      assert inspected =~ "[REDACTED]"
      refute inspected =~ to_string(create!("foo", "bar").private_key)
    end
  end

  describe "leaked?/3" do
    test "reports a leak when the bucket contains the credentials" do
      verification = create!("foo", "bar")

      {reencrypted, prefixes} =
        FakeService.respond(verification, [{"foo", "bar"}, {"baz", "pass"}])

      assert Verification.leaked?(verification, reencrypted, prefixes)
    end

    test "reports no leak when the password differs" do
      verification = create!("foo", "bar")

      {reencrypted, prefixes} =
        FakeService.respond(verification, [{"foo", "diff_password"}, {"baz", "pass"}])

      refute Verification.leaked?(verification, reencrypted, prefixes)
    end

    test "reports no leak for an empty bucket" do
      verification = create!("foo", "bar")
      {reencrypted, []} = FakeService.respond(verification, [])

      refute Verification.leaked?(verification, reencrypted, [])
    end

    # Proof the short-circuit is live: an empty bucket is already the answer, so the reencrypted
    # hash is never decrypted and never has to be a valid point.
    test "an empty bucket answers without touching the reencrypted hash" do
      verification = create!("foo", "bar")

      refute Verification.leaked?(verification, "not a valid curve point", [])
    end

    test "ignores empty prefixes" do
      verification = create!("foo", "bar")
      {reencrypted, _} = FakeService.respond(verification, [])

      refute Verification.leaked?(verification, reencrypted, [""])
    end

    test "ignores a prefix longer than the hash it would match against" do
      verification = create!("foo", "bar")
      {reencrypted, _} = FakeService.respond(verification, [])

      refute Verification.leaked?(verification, reencrypted, [:crypto.strong_rand_bytes(33)])
    end

    test "a raw address canonicalized by the facade matches the canonical leak entry" do
      {:ok, verification} =
        RecaptchaPasswordCheck.create_verification("Foo.Bar@example.com", "bar")

      {reencrypted, prefixes} = FakeService.respond(verification, [{"foobar", "bar"}])

      assert Verification.leaked?(verification, reencrypted, prefixes)
    end

    test "another verification's key cannot read the response" do
      verification = create!("foo", "bar")
      {reencrypted, prefixes} = FakeService.respond(verification, [{"foo", "bar"}])
      other = create!("foo", "bar")

      refute Verification.leaked?(other, reencrypted, prefixes)
    end

    test "rejects an empty reencrypted hash" do
      verification = create!("foo", "bar")

      assert_raise FunctionClauseError, fn -> Verification.leaked?(verification, "", [<<1>>]) end
    end
  end

  describe "canonicalize_username/1" do
    test "leaves lowercase ASCII alone" do
      assert Verification.canonicalize_username("test") == "test"
    end

    test "lowercases ASCII" do
      assert Verification.canonicalize_username("Test") == "test"
    end

    test "strips dots" do
      assert Verification.canonicalize_username("test.test") == "testtest"
    end

    test "strips an email host" do
      assert Verification.canonicalize_username("test@example.com") == "test"
    end

    test "strips the host before stripping dots" do
      assert Verification.canonicalize_username("test.name@ex.com") == "testname"
    end

    test "does not case-fold non-ASCII characters" do
      assert Verification.canonicalize_username("äöü日本語العَرَبِيَّة") == "äöü日本語العَرَبِيَّة"
    end

    # Mixed scripts in one username: the ASCII letters fold, the rest is left untouched. Using
    # String.downcase/1 here instead of a byte-wise fold would silently diverge from the reference.
    test "folds only the ASCII portion of a mixed username" do
      assert Verification.canonicalize_username("Änna.Smith@example.com") == "Ännasmith"
    end

    test "strips an internationalized host" do
      assert Verification.canonicalize_username("例え@例え.テスト") == "例え"
    end

    test "keeps only the part before the first @" do
      assert Verification.canonicalize_username("a@b@c") == "a"
    end

    test "yields an empty username when the local part is empty" do
      assert Verification.canonicalize_username("@nolocalpart") == ""
    end

    test "is idempotent" do
      for username <- ["Foo.Bar@example.com", "a@b@c", "äöü", "@nolocalpart"] do
        once = Verification.canonicalize_username(username)

        assert Verification.canonicalize_username(once) == once
      end
    end
  end
end
