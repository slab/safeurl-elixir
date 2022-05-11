defmodule DNSResolver do
  @callback resolve(String.t) :: {atom, list}
end