# Migrating from 0.3 to 1.0

### Replace `SafeURL.get/4` with `SafeURL.HTTPoison.get/3`

`SafeURL.get/4` has been replaced with `SafeURL.HTTPoison.get/3`. It is now a
drop-in replacement for `HTTPoison.get/3` and thus does not support passing
`SafeURL` options through function arguments.

### Account for new error messages or use `:detailed_error` option

`SafeURL.validate/2` now returns a more specific error by default:

```elixir
iex> SafeURL.validate("http://localhost")
{:error, :unsafe_reserved}
iex> SafeURL.validate("http://google.com", schemes: [:https])
{:error, :unsafe_scheme}
```

You can use the `:detailed_error` configuration option to restore the previous
behavior and get the generic `{:error, :restricted}` error:

```elixir
iex> SafeURL.validate("http://localhost", detailed_error: false)
{:error, :restricted}
iex> Application.put_env(:safeurl, :detailed_error, false)
:ok
iex> SafeURL.validate("http://localhost")
{:error, :restricted}
```
