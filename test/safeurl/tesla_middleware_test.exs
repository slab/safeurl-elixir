defmodule SafeURL.TeslaMiddlewareTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias SafeURL.TeslaMiddleware

  test "can pass options" do
    Tesla.Mock.mock(fn _ -> %Tesla.Env{status: 200} end)

    client =
      Tesla.client(
        [{TeslaMiddleware, [allowlist: ["127.0.0.0/16"], dns_module: TestDNSResolver]}],
        Tesla.Mock
      )

    assert {:ok, %{status: 200}} = Tesla.get(client, "http://blocked_but_allowlisted")
  end

  test "works with other middleware" do
    client =
      Tesla.client([Tesla.Middleware.Logger, {TeslaMiddleware, dns_module: TestDNSResolver}])

    assert capture_log(fn ->
             assert {:error, :restricted} = Tesla.get(client, "http://blocked")
           end) =~ "http://blocked -> error: :restricted"
  end
end
