if Code.ensure_loaded?(HTTPoison) do
  defmodule SafeURL.HTTPoison do
    @moduledoc since: "1.0.0"
    @moduledoc """
    A utility module that should be a drop-in replacement for `HTTPoison`. Only
    supports `get/3`.
    """

    @doc since: "1.0.0"
    @doc """
    Validate a URL and execute a GET request using `HTTPoison`.

    If the URL is safe, this function will execute the request using
    `HTTPoison`, returning the result directly. Otherwise, it will
    return error.

    `headers` and `options` will be passed directly to
    `HTTPoison` when the request is executed.

    ## Examples

        iex> SafeURL.HTTPoison.get("https://10.0.0.1/ssrf.txt")
        {:error, :unsafe_reserved}

        iex> SafeURL.HTTPoison.get("https://google.com/")
        {:ok, %HTTPoison.Response{...}}

    """
    @spec get(binary(), HTTPoison.headers(), Keyword.t()) ::
            {:ok, HTTPoison.Response.t()}
            | {:error, HTTPoison.Error.t()}
            | {:error, SafeURL.error()}
            | {:error, :restricted}
    def get(url, headers \\ [], options \\ []) do
      with :ok <- SafeURL.validate(url) do
        HTTPoison.get(url, headers, options)
      end
    end
  end
end
