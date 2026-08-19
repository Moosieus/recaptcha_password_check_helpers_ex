defmodule RecaptchaPasswordCheck.CanaryTest do
  use ExUnit.Case, async: false

  @moduledoc """
  The only test that talks to the live service.

  Parity fixtures prove this implementation matches Google's *library*. This proves it still
  matches Google's *server*, which is the failure the fixtures cannot see: if the protocol ever
  changes, the credential below stops being reported as leaked. Worth running on a schedule, not
  just on demand.

  Authenticate with a short-lived access token, which avoids creating and restricting an API key:

      RECAPTCHA_PROJECT_ID=my-project \\
        GOOGLE_CLOUD_ACCESS_TOKEN=$(gcloud auth print-access-token) \\
        mix test --only integration

  Or with an API key, which must belong to the same project and either be unrestricted or scoped
  to the reCAPTCHA Enterprise API:

      RECAPTCHA_PROJECT_ID=my-project GOOGLE_CLOUD_API_KEY=AIza... mix test --only integration

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
      RecaptchaPasswordCheck.create_verification("leakedusername", "leakedpassword")

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
      RecaptchaPasswordCheck.create_verification("GabeN@valvesoftware.com", "MoolyFTW")

    assert assess(verification, context)
  end

  test "a randomly generated credential is not reported as leaked", context do
    password = 24 |> :crypto.strong_rand_bytes() |> Base.encode64()

    {:ok, verification} =
      RecaptchaPasswordCheck.create_verification("my-test-username", password)

    refute assess(verification, context)
  end

  # A bearer token wins when both are set: it is short-lived, carries the caller's own IAM
  # permissions, and sidesteps the application and API restrictions that make keys fail in ways
  # the error message does not explain.
  defp auth_headers do
    with :missing <- bearer(System.get_env("GOOGLE_CLOUD_ACCESS_TOKEN")) do
      api_key(System.get_env("GOOGLE_CLOUD_API_KEY"))
    end
  end

  defp bearer(token) do
    with {:ok, token} <- present(token), do: {:ok, [{"authorization", "Bearer " <> token}]}
  end

  defp api_key(key) do
    with {:ok, key} <- present(key), do: {:ok, [{"x-goog-api-key", key}]}
  end

  # Trimming matters: a credential pasted into a shell or read from a file routinely carries a
  # trailing newline, and Google rejects that as an invalid key rather than saying why.
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

    object = Map.fetch!(response.body, "privatePasswordLeakVerification")

    RecaptchaPasswordCheck.leaked?(
      verification,
      Base.decode64!(Map.fetch!(object, "reencryptedUserCredentialsHash")),
      object |> Map.get("encryptedLeakMatchPrefixes", []) |> Enum.map(&Base.decode64!/1)
    )
  end

  defp usage do
    """
    The canary needs RECAPTCHA_PROJECT_ID, plus one of GOOGLE_CLOUD_ACCESS_TOKEN (preferred) or
    GOOGLE_CLOUD_API_KEY:

        RECAPTCHA_PROJECT_ID=my-project \\
          GOOGLE_CLOUD_ACCESS_TOKEN=$(gcloud auth print-access-token) \\
          mix test --only integration
    """
  end
end
