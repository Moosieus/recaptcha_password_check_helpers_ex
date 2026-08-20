defmodule RecaptchaPasswordCheck.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/Moosieus/recaptcha_password_check_helpers_ex"

  def project do
    [
      app: :recaptcha_password_check,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "RecaptchaPasswordCheck",
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  defp deps do
    [
      {:scrypt, "~> 2.1"},
      {:req, "~> 0.5", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp description do
    "Client-side cryptography for reCAPTCHA's private password leak check, a workalike of Google's java-recaptcha-password-check-helpers."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md CHANGELOG.md TESTING.md LICENSE NOTICE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md", "TESTING.md"],
      source_ref: "v#{@version}"
    ]
  end
end
