defmodule SafeURL do
  @moduledoc """
  `SafeURL` is library for mitigating Server Side Request
  Forgery vulnerabilities in Elixir. Private/reserved IP
  addresses are blacklisted by default, and users can add
  additional CIDR ranges to blacklist, or alternatively
  whitelist specific CIDR ranges to which the application is
  allowed to make requests.

  You can use `allowed?/2` or `validate/2` to check if a
  URL is safe to call, or just call it directly via `get/4`
  which will validate it automatically before calling, and
  return an error if it is not.


  ## Examples

      iex> SafeURL.allowed?("https://includesecurity.com")
      true

      iex> SafeURL.validate("http://google.com/", schemes: ~w[https])
      {:error, :restricted}

      iex> SafeURL.validate("http://230.10.10.10/")
      {:error, :restricted}

      iex> SafeURL.validate("http://230.10.10.10/", blacklist_reserved: false)
      :ok

      iex> SafeURL.get("https://10.0.0.1/ssrf.txt")
      {:error, :restricted}

      iex> SafeURL.get("https://google.com/")
      {:ok, %HTTPoison.Response{...}}


  ## Options

  `SafeURL` can be configured to customize and override
  validation behaviour by passing the following options:

    * `:blacklist_reserved` - Blacklist reserved/private IP
      ranges. Defaults to `true`.

    * `:blacklist` - List of CIDR ranges to blacklist. This is
      additive with `:blacklist_reserved`. Defaults to `[]`.

    * `:whitelist` - List of CIDR ranges to whitelist. If
      specified, blacklists will be ignored. Defaults to `[]`.

    * `:schemes` - List of allowed URL schemes. Defaults to
      `["http, "https"]`.

  If `:blacklist_reserved` is `true` and additional hosts/ranges
  are supplied with `:blacklist`, both of them are included in
  the final blacklist to validate the address. If whitelisted
  ranges are supplied with `:whitelist`, all blacklists are
  ignored and any hosts not explicitly declared in the whitelist
  are rejected.

  These options can be set globally in your `config.exs` file:

      config :safeurl,
        blacklist_reserved: true,
        blacklist: ~w[100.0.0.0/16],
        schemes: ~w[https]

  Or they can be passed to the function directly, overriding any
  global options if set:

      iex> SafeURL.validate("http://10.0.0.1/", blacklist_reserved: false)
      :ok

      iex> SafeURL.validate("https://app.service/", whitelist: ~w[170.0.0.0/24])
      :ok

      iex> SafeURL.validate("https://app.service/", blacklist: ~w[170.0.0.0/24])
      {:error, :restricted}

  """

  @reserved_ranges [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/29",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4"
  ]



  # Public API
  # ----------


  @doc """
  Validate a string URL against a blacklist or whitelist.

  This method checks if a URL is safe to be called by looking at
  its scheme and resolved IP address, and matching it against
  reserved CIDR ranges, and any provided whitelist/blacklist.

  Returns `true` if the URL meets the requirements,
  `false` otherwise.

  ## Examples

      iex> SafeURL.allowed?("https://includesecurity.com")
      true

      iex> SafeURL.allowed?("http://10.0.0.1/")
      false

      iex> SafeURL.allowed?("http://10.0.0.1/", whitelist: ~w[10.0.0.0/8])
      true

  ## Options

  See [`Options`](#module-options) section above.

  """
  @spec allowed?(binary(), Keyword.t()) :: boolean()
  def allowed?(url, opts \\ []) do
    uri = URI.parse(url)
    opts = build_options(opts)
    address = resolve_address(uri.host)

    cond do
      uri.scheme not in opts.schemes ->
        false

      opts.whitelist != [] ->
        ip_in_ranges?(address, opts.whitelist)

      true ->
        !ip_in_ranges?(address, opts.blacklist)
    end
  end


  @doc """
  Alternative method of validating a URL, returning atoms instead
  of booleans.

  This calls `allowed?/2` underneath to check if a URL is safe to
  be called. If it is, it returns `:ok`, otherwise
  `{:error, :restricted}`.

  ## Examples

      iex> SafeURL.validate("https://includesecurity.com")
      :ok

      iex> SafeURL.validate("http://10.0.0.1/")
      {:error, :restricted}

      iex> SafeURL.validate("http://10.0.0.1/", whitelist: ~w[10.0.0.0/8])
      :ok

  ## Options

  See [`Options`](#module-options) section above.

  """
  @spec validate(binary(), Keyword.t()) :: :ok | {:error, :restricted}
  def validate(url, opts \\ []) do
    if allowed?(url, opts) do
      :ok
    else
      {:error, :restricted}
    end
  end


  @doc """
  Validate a URL and execute a GET request using `HTTPoison`.

  If the URL is safe, this function will execute the request using
  `HTTPoison`, returning the result directly. Otherwise, it will
  return `{:error, :restricted}`.

  `headers` and `httpoison_options` will be passed directly to
  `HTTPoison` when the request is executed.

  See `allowed?/2` for more details on URL validation.

  ## Examples

      iex> SafeURL.get("https://10.0.0.1/ssrf.txt")
      {:error, :restricted}

      iex> SafeURL.get("https://google.com/")
      {:ok, %HTTPoison.Response{...}}

      iex> SafeURL.get("https://google.com/", schemes: ~w[ftp])
      {:error, :restricted}

  ## Options

  See [`Options`](#module-options) section above.

  """
  @spec get(binary(), Keyword.t(), HTTPoison.headers(), Keyword.t()) ::
          {:ok, HTTPoison.Response.t()} | {:error, :restricted}
  def get(url, options \\ [], headers \\ [], httpoison_options \\ []) do
    with :ok <- validate(url, options) do
      HTTPoison.get(url, headers, httpoison_options)
    end
  end




  # Private Helpers
  # ---------------


  # Return a map of calculated options
  defp build_options(opts) do
    schemes = get_option(opts, :schemes)
    whitelist = get_option(opts, :whitelist)
    blacklist = get_option(opts, :blacklist)

    blacklist =
      if get_option(opts, :blacklist_reserved) do
        blacklist ++ @reserved_ranges
      else
        blacklist
      end

    %{schemes: schemes, whitelist: whitelist, blacklist: blacklist}
  end


  # Get the value of a specific option, either from the application
  # configs or overrides explicitly passed as arguments.
  defp get_option(opts, key) do
    if Keyword.has_key?(opts, key) do
      Keyword.get(opts, key)
    else
      Application.get_env(:safeurl, key)
    end
  end


  # Resolve hostname in DNS to an IP address (if not already an IP)
  defp resolve_address(hostname) do
    hostname
    |> to_charlist()
    |> :inet.parse_address()
    |> case do
      {:ok, ip} ->
        ip

      {:error, :einval} ->
        # TODO: safely handle multiple IPs/round-robin DNS
        case DNS.resolve(hostname) do
          {:ok, ips} -> List.first(ips)
          {:error, _reason} -> nil
        end
    end
  end


  defp ip_in_ranges?({_, _, _, _} = addr, ranges) when is_list(ranges) do
    Enum.any?(ranges, fn range ->
      range
      |> InetCidr.parse()
      |> InetCidr.contains?(addr)
    end)
  end

  defp ip_in_ranges?(_addr, _ranges), do: false
end
