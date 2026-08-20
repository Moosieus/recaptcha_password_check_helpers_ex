defmodule RecaptchaPasswordCheck.ParityTest do
  use ExUnit.Case, async: true

  alias RecaptchaPasswordCheck.CryptoHelper
  alias RecaptchaPasswordCheck.EcCommutativeCipher, as: Cipher

  @moduledoc """
  Byte-for-byte comparison against Google's Java implementation.

  Every stage of the pipeline is compared, not just the final payload, so a
  failure names the step that diverged. Regenerate with `parity/regenerate.sh`;
  Java and Docker are needed only for that, never to run this suite.
  """

  @fixture Path.join(__DIR__, "fixtures/parity_vectors.json")
  @external_resource @fixture

  defp hex(binary), do: Base.encode16(binary, case: :lower)
  defp unhex(string), do: Base.decode16!(string, case: :mixed)
  defp key(string), do: string |> unhex() |> :binary.decode_unsigned()

  if File.exists?(@fixture) do
    setup_all do
      %{"vectors" => vectors} = @fixture |> File.read!() |> JSON.decode!()

      {:ok, vectors: vectors}
    end

    test "the fixture covers the cases that the live canary cannot", %{vectors: vectors} do
      usernames = Enum.map(vectors, & &1["username"])

      assert "äöü日本語العَرَبِيَّة" in usernames
      assert "test.name@ex.com" in usernames
      assert "例え@例え.テスト" in usernames
      assert length(vectors) >= 13
    end

    test "canonicalization matches", %{vectors: vectors} do
      for vector <- vectors do
        assert RecaptchaPasswordCheck.canonicalize_username(vector["username"]) ==
                 vector["canonicalized_username"],
               "canonicalization diverged for #{inspect(vector["username"])}"
      end
    end

    test "username hash matches", %{vectors: vectors} do
      for %{"canonicalized_username" => canonical} = vector <- vectors do
        assert hex(CryptoHelper.hash_username(canonical)) == vector["username_hash_hex"],
               "username hash diverged for #{inspect(vector["username"])}"
      end
    end

    test "bucket prefix matches", %{vectors: vectors} do
      for %{"canonicalized_username" => canonical} = vector <- vectors do
        bucket = hex(CryptoHelper.bucketize_username(canonical))

        assert bucket == vector["lookup_hash_prefix_hex"],
               "bucket prefix diverged for #{inspect(vector["username"])}"
      end
    end

    test "scrypt credentials hash matches", %{vectors: vectors} do
      for %{"canonicalized_username" => canonical} = vector <- vectors do
        assert hex(CryptoHelper.hash_username_password_pair(canonical, vector["password"])) ==
                 vector["credentials_hash_hex"],
               "credentials hash diverged for #{inspect(vector["username"])}"
      end
    end

    test "hash-to-curve matches", %{vectors: vectors} do
      for vector <- vectors do
        credentials_hash = unhex(vector["credentials_hash_hex"])

        assert hex(Cipher.hash_into_the_curve(credentials_hash)) == vector["hash_into_curve_hex"],
               "hash-to-curve diverged for #{inspect(vector["username"])}"
      end
    end

    test "client encryption matches", %{vectors: vectors} do
      for vector <- vectors do
        credentials_hash = unhex(vector["credentials_hash_hex"])
        client_key = key(vector["client_private_key_hex"])

        assert hex(Cipher.encrypt(client_key, credentials_hash)) ==
                 vector["encrypted_credentials_hash_hex"],
               "client encryption diverged for #{inspect(vector["username"])}"
      end
    end

    test "server re-encryption matches", %{vectors: vectors} do
      for vector <- vectors do
        server_key = key(vector["server_private_key_hex"])
        encrypted = unhex(vector["encrypted_credentials_hash_hex"])

        assert hex(Cipher.re_encrypt(server_key, encrypted)) == vector["server_reencrypted_hex"],
               "re-encryption diverged for #{inspect(vector["username"])}"
      end
    end

    test "client decryption and re-hashing match", %{vectors: vectors} do
      for vector <- vectors do
        client_key = key(vector["client_private_key_hex"])
        reencrypted = unhex(vector["server_reencrypted_hex"])

        decrypted = Cipher.decrypt(client_key, reencrypted)

        assert hex(decrypted) == vector["client_decrypted_hex"],
               "decryption diverged for #{inspect(vector["username"])}"

        assert hex(CryptoHelper.hash_blinded_hash(decrypted)) == vector["rehashed_decrypted_hex"],
               "re-hash diverged for #{inspect(vector["username"])}"
      end
    end

    test "the server's match prefix prefixes our re-hashed value", %{vectors: vectors} do
      for vector <- vectors do
        assert String.starts_with?(
                 vector["rehashed_decrypted_hex"],
                 vector["server_match_prefix_hex"]
               ),
               "prefix relationship broken for #{inspect(vector["username"])}"
      end
    end

    # The client key cancels out of the exchange — `c⁻¹ · s · c · H(m) == s · H(m)` — so a key
    # generated inside `create/2` still has to land on Java's post-decryption value. That covers
    # the composed payload end to end without the public API accepting a key.
    test "a freshly keyed verification reproduces Java's decrypted value", %{vectors: vectors} do
      # The facade refuses a username that canonicalizes to nothing, so that vector cannot travel
      # this path. Its hashes stay covered by the stage-level tests above, which read the canonical
      # form straight from the fixture.
      for vector <- vectors, vector["canonicalized_username"] != "" do
        {:ok, verification} =
          RecaptchaPasswordCheck.create(vector["username"], vector["password"])

        server_key = key(vector["server_private_key_hex"])
        reencrypted = Cipher.re_encrypt(server_key, verification.encrypted_user_credentials_hash)

        rehashed =
          verification.private_key
          |> Cipher.decrypt(reencrypted)
          |> CryptoHelper.hash_blinded_hash()

        assert hex(verification.lookup_hash_prefix) == vector["lookup_hash_prefix_hex"],
               "composed bucket prefix diverged for #{inspect(vector["username"])}"

        assert hex(rehashed) == vector["rehashed_decrypted_hex"],
               "key cancellation diverged for #{inspect(vector["username"])}"
      end
    end

    test "a Java-produced match prefix is read as leaked", %{vectors: vectors} do
      # The facade refuses a username that canonicalizes to nothing, so that vector cannot travel
      # this path. Its hashes stay covered by the stage-level tests above, which read the canonical
      # form straight from the fixture.
      for vector <- vectors, vector["canonicalized_username"] != "" do
        {:ok, verification} =
          RecaptchaPasswordCheck.create(vector["username"], vector["password"])

        server_key = key(vector["server_private_key_hex"])
        reencrypted = Cipher.re_encrypt(server_key, verification.encrypted_user_credentials_hash)

        assert RecaptchaPasswordCheck.leaked?(verification, reencrypted, [
                 unhex(vector["server_match_prefix_hex"])
               ]),
               "leaked?/3 missed a known match for #{inspect(vector["username"])}"
      end
    end

    test "an unrelated match prefix is not read as leaked", %{vectors: vectors} do
      # The facade refuses a username that canonicalizes to nothing, so that vector cannot travel
      # this path. Its hashes stay covered by the stage-level tests above, which read the canonical
      # form straight from the fixture.
      for vector <- vectors, vector["canonicalized_username"] != "" do
        {:ok, verification} =
          RecaptchaPasswordCheck.create(vector["username"], vector["password"])

        server_key = key(vector["server_private_key_hex"])
        reencrypted = Cipher.re_encrypt(server_key, verification.encrypted_user_credentials_hash)

        refute RecaptchaPasswordCheck.leaked?(verification, reencrypted, [
                 binary_part(:crypto.hash(:sha256, "unrelated"), 0, 20)
               ])
      end
    end
  else
    @tag :skip
    test "parity vectors are absent — run parity/regenerate.sh" do
      flunk("missing #{@fixture}")
    end
  end
end
