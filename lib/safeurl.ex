defmodule SafeURL do
  @moduledoc """
  A library for mitigating Server Side Request Forgery vulnerabilities in Elixir. Private/reserved
  IP addresses are blacklisted by default, and users can add additional CIDR ranges to blacklist
  or alternatively whitelist specific CIDR ranges to which the application is allowed to make requests.

  Examples:

    iex(10)> SafeURL.get("https://10.0.0.1/ssrf.txt")
    {:error, :restricted}

    iex(10)> SafeURL.get("https://google.com/")
    {:ok,
    %HTTPoison.Response{
      body: "{...}",
      headers: [
        {"..."}
      ],
      request: %HTTPoison.Request{
        body: "",
        headers: [],
        method: :get,
        options: [],
        params: %{},
        url: "https://google.com/"
      },
      request_url: "https://google.com/",
      status_code: 301
    }}
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

  @doc """
  Validate a URL and execute a GET request using `HTTPoison` with the specified headers and options.

  Available options and defaults:
  * `:blacklist_private` - Blacklist private/reserved IP ranges (default: `true`)
  * `:blacklist` - List of CIDR ranges to blacklist. Additive with `:blacklist_private` (default: `nil`)
  * `:whitelist` - List of CIDR ranges to whitelist. If specified, blacklists will be ignored (default: `nil`)
  * `:schemes` - List of valid URL schemes (default: `["http, "https"]`)

  Options specified in `httpoison_options` will be passed directly to `HTTPoison` when the request is executed.

  If `:blacklist_private` is `true` and additional hosts/ranges are supplied with `:blacklist`, the
  lists are additive. If whitelisted ranges are supplied with `:whitelist`, all blacklists are ignored
  and any hosts not explicitly declared in the whitelist are rejected.

  If the URL is safe, this function returns the `HTTPoison` result directly; otherwise, `{:error, :restricted}`.
  """
  def get(url, options \\ [], headers \\ [], httpoison_options \\ []) do
    if validate_url(url, options) do
      HTTPoison.get(url, headers, httpoison_options)
    else
      {:error, :restricted}
    end
  end

  @doc """
  Validate a string URL against a blacklist or whitelist.

  See documentation for `SafeURL.get()` for available options and defaults.

  Returns `true` if the URL meets the requirements, `false` otherwise.
  """
  def validate_url(url, options \\ []) do
    blacklist_private = Keyword.get(options, :blacklist_private, true)
    blacklist = Keyword.get(options, :blacklist, [])
    whitelist = Keyword.get(options, :whitelist, [])
    schemes = Keyword.get(options, :schemes, ["http", "https"])
    host_info = URI.parse(url)

    # TODO: Refactor this to use idiomatic elixir control flow
    if validate_scheme(host_info.scheme, schemes) == false do
      false
    else
      addr = resolve_address(host_info.host)
      if length(whitelist) != 0 do
        validate_whitelist(addr, whitelist)
      else
        if blacklist_private == false do
          validate_blacklist(addr, blacklist)
        else
          validate_blacklist(addr, @reserved_ranges ++ blacklist)
        end
      end
    end
  end

  defp resolve_address(hostname) do
    # Don't resolve hostname in DNS if it's an IP address
    {result, value} = hostname |> to_charlist() |> :inet.parse_address()
    if result != :ok do
      {_, ip} = DNS.resolve(hostname)
      # TODO: safely handle multiple IPs/round-robin DNS
      List.first(ip)
    else
      value
    end
  end

  defp validate_scheme(scheme, allowed_schemes) do
    Enum.member?(allowed_schemes, scheme)
  end

  defp validate_whitelist(address, whitelist) do
    Enum.any?(whitelist, fn range ->
      InetCidr.contains?(InetCidr.parse(range), address)
    end)
  end

  defp validate_blacklist(address, blacklist) do
    !Enum.any?(blacklist, fn range ->
      InetCidr.contains?(InetCidr.parse(range), address)
    end)
  end
end
