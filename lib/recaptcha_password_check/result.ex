defmodule RecaptchaPasswordCheck.Result do
  @moduledoc """
  The outcome of a password check.

  The protocol answers exactly one question, so `leaked?` is the whole verdict —
  there is no breach name, date, or count to report.
  """

  @enforce_keys [:username, :leaked?]
  defstruct @enforce_keys
end
