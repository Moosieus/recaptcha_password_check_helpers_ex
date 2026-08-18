defmodule RecaptchaPasswordCheck.Scrypt do
  @moduledoc """
  Thin wrapper over the scrypt NIF.

  Erlang's `:crypto` offers PBKDF2 but not scrypt, so this is the one native
  dependency the library carries. The NIF is registered as a dirty CPU-bound job,
  so it will not block a normal scheduler.

  Isolated in its own module so swapping implementations touches one file.
  """

  @doc """
  Derives `length` bytes from `password` and `salt`.

  `n` is the CPU/memory cost, `r` the block size, `p` the parallelization factor.
  """
  def derive(password, salt, n, r, p, length)
      when is_binary(password) and is_binary(salt) and is_integer(n) and is_integer(r) and
             is_integer(p) and is_integer(length) do
    :scrypt.scrypt(password, salt, n, r, p, length)
  end
end
