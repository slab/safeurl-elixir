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



  # Public API
  # ----------


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
    if allowed?(url, options) do
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
  @spec allowed?(binary(), Keyword.t()) :: boolean()
  def allowed?(url, opts \\ []) do
    uri = URI.parse(url)
    opts = build_options(opts)
    ip = resolve_address(uri.host)

    cond do
      uri.scheme not in opts.schemes ->
        false

      opts.whitelist != [] ->
        ip_in_ranges?(address, opts.whitelist)

      true ->
        !ip_in_ranges?(address, opts.blacklist)
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
