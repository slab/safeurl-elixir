if Code.ensure_loaded?(HTTPoison) do
  defmodule SafeURL.HTTPoison do
    @moduledoc """
    A utility module that should be a drop-in replacement for `HTTPoison`. Only
    supports `get/3`.
    """

    @doc """
    Validate a URL and execute a GET request using `HTTPoison`.

    If the URL is safe, this function will execute the request using
    `HTTPoison`, returning the result directly. Otherwise, it will
    return `{:error, :restricted}`.

    `headers` and `options` will be passed directly to
    `HTTPoison` when the request is executed. This function will
    raise if `HTTPoison` if not available.

    ## Examples

        iex> SafeURL.HTTPoison.get("https://10.0.0.1/ssrf.txt")
        {:error, :restricted}

        iex> SafeURL.HTTPoison.get("https://google.com/")
        {:ok, %HTTPoison.Response{...}}

        iex> SafeURL.HTTPoison.get("https://google.com/", schemes: ~w[ftp])
        {:error, :restricted}

    """
    @spec get(binary(), HTTPoison.headers(), Keyword.t()) ::
            {:ok, HTTPoison.Response.t()} | {:error, HTTPoison.Error.t()} | {:error, :restricted}
    def get(url, headers \\ [], options \\ []) do
      with :ok <- SafeURL.validate(url) do
        HTTPoison.get(url, headers, options)
      end
    end
  end
end
