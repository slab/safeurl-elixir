if Code.ensure_loaded?(Tesla) do
  defmodule SafeURL.TeslaMiddleware do
    @moduledoc """
    Tesla middleware for validating URLs.

    ## Examples

        iex> Tesla.client([SafeURL.TeslaMiddleware]) |> Tesla.get("http://localhost/")
        {:error, :restricted}
    """
    @behaviour Tesla.Middleware

    def call(%Tesla.Env{url: url} = env, next, options) do
      with :ok <- SafeURL.validate(url, options) do
        Tesla.run(env, next)
      end
    end
  end
end
