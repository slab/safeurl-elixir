defmodule TestDNSResolver do
  @behaviour SafeURL.DNSResolver

  @impl true
  def resolve(_any), do: {:ok, [{127, 0, 0, 1}]}
end
