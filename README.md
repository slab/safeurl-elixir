SafeURL
=======

<!--[![Build Status][badge-github]][github-build]-->
[![Version][badge-version]][hexpm]
[![Downloads][badge-downloads]][hexpm]
[![License][badge-license]][github-license]


> SSRF Protection in Elixir 🛡️


SafeURL is a library that aids developers in protecting against a class of vulnerabilities
known as Server Side Request Forgery. It does this by validating a URL against a configurable
allow or block list before making an HTTP request. SafeURL is open-source and licensed under
MIT.

This library was originally created by Nick Fox at [Include Security][includesecurity],
with substantial improvements contributed by the [Slab][slab] team. As of January 2022, this
library is now officially maintained by Slab.

See the [Documentation][docs] on HexDocs.

<br>




## Installation

Add `safeurl` to your project dependencies in `mix.exs`:

```elixir
def deps do
  [{:safeurl, "~> 0.1.0"}]
end
```

<br>




## Usage

`SafeURL` blocks private/reserved IP addresses are by default, and users can add additional
CIDR ranges to the blocklist, or alternatively allow specific CIDR ranges to which the
application is allowed to make requests.

You can use `allowed?/2` or `validate/2` to check if a URL is safe to call, or just call
it directly via `get/4` which will validate it automatically before calling, and return an
error if it is not.


### Examples

```elixir
iex> SafeURL.allowed?("https://includesecurity.com")
true

iex> SafeURL.validate("http://google.com/", schemes: ~w[https])
{:error, :restricted}

iex> SafeURL.validate("http://230.10.10.10/")
{:error, :restricted}

iex> SafeURL.validate("http://230.10.10.10/", block_reserved: false)
:ok

iex> SafeURL.get("https://10.0.0.1/ssrf.txt")
{:error, :restricted}

iex> SafeURL.get("https://google.com/")
{:ok, %HTTPoison.Response{...}}
```


### Configuration

`SafeURL` can be configured to customize and override validation behaviour by passing the
following options:

  * `:block_reserved` - Block reserved/private IP ranges. Defaults to `true`.

  * `:blocklist` - List of CIDR ranges to block. This is additive with `:block_reserved`.
    Defaults to `[]`.

  * `:allowlist` - List of CIDR ranges to allow. If specified, blocklist will be ignored.
    Defaults to `[]`.

  * `:schemes` - List of allowed URL schemes. Defaults to `["http, "https"]`.


These options can be passed to the function directly or set globally in your `config.exs`
file:

```elixir
config :safeurl,
  block_reserved: true,
  blocklist: ~w[100.0.0.0/16],
  schemes: ~w[https]
```

Find detailed documentation on [HexDocs][docs].

<!--
  TODO: Add section explaining how to use SafeURL with various HTTP libraries
  such as HTTPoison, Tesla, etc. once we remove HTTPoison as a dependency.
-->

<br>




## Contributing

 - [Fork][github-fork], Enhance, Send PR
 - Lock issues with any bugs or feature requests
 - Implement something from Roadmap
 - Spread the word :heart:

<br>




## License

This package is available as open source under the terms of the [MIT License][github-license].

<br>




<!--[badge-github]:     https://github.com/slab/delta-elixir/actions/workflows/ci.yml/badge.svg-->
[badge-version]:    https://img.shields.io/hexpm/v/safeurl.svg
[badge-license]:    https://img.shields.io/hexpm/l/safeurl.svg
[badge-downloads]:  https://img.shields.io/hexpm/dt/safeurl.svg

[hexpm]:            https://hex.pm/packages/safeurl
[github-license]:   https://github.com/slab/safeurl-elixir/blob/master/LICENSE
[github-fork]:      https://github.com/slab/safeurl-elixir/fork

[docs]:             https://hexdocs.pm/safeurl
[slab]:             https://slab.com/
[includesecurity]:  https://github.com/IncludeSecurity


