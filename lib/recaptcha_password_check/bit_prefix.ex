defmodule RecaptchaPasswordCheck.BitPrefix do
  @moduledoc """
  A bit-level prefix of a binary, truncated from the most significant end.

  The reCAPTCHA protocol identifies a leak bucket by the first 26 bits of a username hash, which
  is not a byte boundary — hence a dedicated representation rather than `binary_part/3`.
  """

  @enforce_keys [:bits, :value]
  defstruct [:bits, :value]

  @doc """
  Takes the leading `bits` bits of `binary`.

  Raises when `binary` holds fewer than `bits` bits.

      iex> RecaptchaPasswordCheck.BitPrefix.of(<<0xCE, 0x8C, 0x59, 0xDF>>, 26) |> RecaptchaPasswordCheck.BitPrefix.to_binary()
      <<0xCE, 0x8C, 0x59, 0xC0>>
  """
  def of(binary, bits) when is_binary(binary) and is_integer(bits) and bits >= 0 do
    if bit_size(binary) < bits do
      raise ArgumentError,
            "invalid length of bytes array: #{bit_size(binary)} bits available, #{bits} requested"
    end

    <<value::unsigned-big-integer-size(bits), _::bitstring>> = binary
    %__MODULE__{bits: bits, value: value}
  end

  @doc """
  Renders the prefix as a binary, zero-filling the trailing bits of the final byte.
  """
  def to_binary(%__MODULE__{bits: bits, value: value}) do
    padding = rem(8 - rem(bits, 8), 8)
    <<value::unsigned-big-integer-size(bits), 0::size(padding)>>
  end

  @doc """
  Renders the prefix as a binary of exactly `byte_count` bytes, zero-filling.
  """
  def to_binary(%__MODULE__{bits: bits, value: value}, byte_count) do
    padding = byte_count * 8 - bits

    if padding < 0 do
      raise ArgumentError, "#{byte_count} bytes cannot hold a #{bits} bit prefix"
    end

    <<value::unsigned-big-integer-size(bits), 0::size(padding)>>
  end

  defimpl String.Chars do
    def to_string(%RecaptchaPasswordCheck.BitPrefix{bits: 0}), do: "Empty prefix"

    def to_string(%RecaptchaPasswordCheck.BitPrefix{bits: bits, value: value}) do
      "0b" <> String.pad_leading(Integer.to_string(value, 2), bits, "0")
    end
  end
end
