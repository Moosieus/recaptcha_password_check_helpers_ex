defmodule RecaptchaPasswordCheck.CanaryTest do
  use ExUnit.Case, async: false

  @moduledoc """
  The only test that talks to the live service.

  Parity fixtures prove this implementation matches Google's *library*. This
  proves it still matches Google's *server*, which is the failure the fixtures
  cannot see: if the protocol ever changes, the credential below stops being
  reported as leaked. Worth running on a schedule, not just on demand.

      RECAPTCHA_PROJECT_ID=... GOOGLE_CLOUD_API_KEY=... mix test --only integration

  Each run bills one assessment against the project, and password defense
  requires the Premium tier.
  """

  @moduletag :integration
  @moduletag timeout: 60_000

  @endpoint "https://recaptchaenterprise.googleapis.com/v1/projects"

  setup_all do
    project = System.get_env("RECAPTCHA_PROJECT_ID")
    api_key = System.get_env("GOOGLE_CLOUD_API_KEY")

    if is_nil(project) or is_nil(api_key) do
      raise """
      RECAPTCHA_PROJECT_ID and GOOGLE_CLOUD_API_KEY must both be set to run the canary.
      """
    end

    {:ok, project: project, api_key: api_key}
  end

  test "the reference leaked credential is still reported as leaked", context do
    verification = RecaptchaPasswordCheck.create_verification("leakedusername", "leakedpassword")

    assert assess(verification, context).leaked?
  end

  test "a randomly generated credential is not reported as leaked", context do
    password = 24 |> :crypto.strong_rand_bytes() |> Base.encode64()
    verification = RecaptchaPasswordCheck.create_verification("my-test-username", password)

    refute assess(verification, context).leaked?
  end

  defp assess(verification, %{project: project, api_key: api_key}) do
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
        headers: [{"x-goog-api-key", api_key}],
        receive_timeout: 30_000
      )

    assert response.status == 200, "assessment failed: #{inspect(response.body)}"

    leak = response.body["privatePasswordLeakVerification"]

    RecaptchaPasswordCheck.verify(
      verification,
      decode64!(leak["reencryptedUserCredentialsHash"]),
      Enum.map(leak["encryptedLeakMatchPrefixes"] || [], &decode64!/1)
    )
  end

  # The REST API is documented as standard base64, but proto JSON emits the
  # URL-safe alphabet in some cases, so accept either.
  defp decode64!(encoded) do
    case Base.decode64(encoded, padding: false) do
      {:ok, decoded} -> decoded
      :error -> Base.url_decode64!(encoded, padding: false)
    end
  end
end
