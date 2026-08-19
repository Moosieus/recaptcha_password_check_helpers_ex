defmodule RecaptchaPasswordCheck.CanaryTest do
  use ExUnit.Case, async: false

  @moduledoc """
  The only test that talks to the live service.

  Parity fixtures prove this implementation matches Google's *library*. This proves it still
  matches Google's *server*, which is the failure the fixtures cannot see: if the protocol ever
  changes, the credential below stops being reported as leaked.

  Authenticate with a short-lived access token which the gcloud CLI hands over directly:

      RECAPTCHA_PROJECT_ID=my-project \\
        GOOGLE_CLOUD_ACCESS_TOKEN=$(gcloud auth print-access-token) \\
        mix test --only integration

  Each run bills one assessment against the project, and password defense requires the Premium
  tier.
  """

  @moduletag :integration
  @moduletag timeout: 60_000

  @endpoint "https://recaptchaenterprise.googleapis.com/v1/projects"

  setup_all do
    project = System.get_env("RECAPTCHA_PROJECT_ID")

    with {:ok, project} <- present(project),
         {:ok, headers} <- auth_headers() do
      {:ok, project: project, headers: headers}
    else
      :missing -> raise usage()
    end
  end

  test "the reference leaked credential is still reported as leaked", context do
    {:ok, verification} =
      RecaptchaPasswordCheck.create("leakedusername", "leakedpassword")

    assert assess(verification, context)
  end

  # The case above may well be a sentinel the service keeps for testing, in which case it proves the
  # protocol round-trips but says nothing about the corpus. These credentials were disclosed
  # publicly in 2011 and have sat in breach compilations ever since, so a match here cannot be
  # explained by a test hook. If this fails while the sentinel passes, suspect the corpus or the
  # bucketing rather than the protocol.
  #
  # https://www.youtube.com/watch?v=gYs9nS8LlZ8
  test "a real-world publicly leaked credential is reported as leaked", context do
    {:ok, verification} =
      RecaptchaPasswordCheck.create("GabeN@valvesoftware.com", "MoolyFTW")

    assert assess(verification, context)
  end

  test "a randomly generated credential is not reported as leaked", context do
    password = 24 |> :crypto.strong_rand_bytes() |> Base.encode64()

    {:ok, verification} =
      RecaptchaPasswordCheck.create("my-test-username", password)

    refute assess(verification, context)
  end

  defp auth_headers do
    with {:ok, token} <- present(System.get_env("GOOGLE_CLOUD_ACCESS_TOKEN")) do
      {:ok, [{"authorization", "Bearer " <> token}]}
    end
  end

  defp present(value) when is_binary(value) do
    case String.trim(value) do
      "" -> :missing
      trimmed -> {:ok, trimmed}
    end
  end

  defp present(_value), do: :missing

  defp assess(verification, %{project: project, headers: headers}) do
    body = %{
      "privatePasswordLeakVerification" => %{
        "lookupHashPrefix" => Base.encode64(verification.lookup_hash_prefix),
        "encryptedUserCredentialsHash" =>
          Base.encode64(verification.encrypted_user_credentials_hash)
      }
    }

    response =
      Req.post!("#{@endpoint}/#{project}/assessments",
        json: body,
        headers: headers,
        receive_timeout: 30_000
      )

    assert response.status == 200, """
    Assessment failed with HTTP #{response.status}:

    #{inspect(response.body, pretty: true)}
    """

    %{"privatePasswordLeakVerification" => leak} = response.body
    %{"reencryptedUserCredentialsHash" => reencrypted_hash} = leak

    reencrypted_hash = Base.decode64!(reencrypted_hash)

    match_prefixes =
      leak |> Map.get("encryptedLeakMatchPrefixes", []) |> Enum.map(&Base.decode64!/1)

    RecaptchaPasswordCheck.leaked?(verification, reencrypted_hash, match_prefixes)
  end

  defp usage do
    """
    The canary needs RECAPTCHA_PROJECT_ID and GOOGLE_CLOUD_ACCESS_TOKEN:

        RECAPTCHA_PROJECT_ID=my-project \\
          GOOGLE_CLOUD_ACCESS_TOKEN=$(gcloud auth print-access-token) \\
          mix test --only integration
    """
  end
end
