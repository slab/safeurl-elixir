# SafeURL
SafeURL is a library that aids developers in protecting against a class of vulnerabilities known as Server Side Request Forgery. It does this by validating a URL against a configurable white or black list before making an HTTP request. SafeURL is open-source and licensed under MIT.

## Installation
This package is not yet available in hex, so it must be installed from GitHub by adding the following to 
`mix.exs`:

```elixir
def deps do
  [
    {:safeurl, github: "includesecurity/elixir-safeurl"}
  ]
end
```

## Usage
SafeURL wraps around [HTTPoison](https://github.com/edgurgel/httpoison) and
works by resolving the IP address from a supplied URL and validating it
against a blacklist or whitelist before sending the request. By default, all
internal/reserved CIDR ranges are blacklisted, and developers can add
additional CIDR ranges to these lists with the `:blacklist` parameter, or 
instead use a whitelist approach with `:whitelist`. 

```elixir
# Only block private IP ranges
iex> SafeURL.get("https://includesecurity.com")
{:ok, %HTTPoison.Response{...}}

# Blacklist 8.8.0.0/16 in addition to all private ranges
iex> SafeURL.get("https://includsecurity.com", blacklist: ["8.8.0.0/16"])
{:ok, %HTTPoison.Response{...}}

# Only allow requests to hosts on 10.0.0.0/24
iex> SafeURL.get("https://includesecurity.com", whitelist: ["10.0.0.0/24"])
{:error, :restricted}

# Pass some headers and options to HTTPoison
iex> SafeURL.get("https://includesecurity.com", [], [{"User-Agent", "elixir/1.11.3"}], follow_redirect: false)
```

If you only need to validate a URL and want to make the request yourself, you
can use `SafeURL.validate_url()` instead:

```elixir
iex> SafeURL.validate_url("https://acme.corp.internal")
{:error, :restricted}
```