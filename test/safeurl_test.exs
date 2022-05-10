defmodule TestDNSResolver do
  @behaviour DNSResolver

  @impl DNSResolver
  def resolve(_domain), do: {:ok, [{192, 0, 78, 24}]}
end

defmodule SafeURLTest do
  use ExUnit.Case

  # setup_all do
  #   global_whitelist = ["10.0.0.0/24"]
  #   global_blacklist = ["8.8.0.0/16"]

  #   Application.put_env(:safeurl, :whitelist, global_whitelist)
  # end

  describe "#allowed?" do
    test "returns true for only allowed schemes" do
      assert SafeURL.allowed?("http://includesecurity.com", dns_module: TestDNSResolver)
      assert SafeURL.allowed?("https://includesecurity.com", dns_module: TestDNSResolver)
      refute SafeURL.allowed?("ftp://includesecurity.com", dns_module: TestDNSResolver)

      assert SafeURL.allowed?("ftp://includesecurity.com", schemes: ~w[ftp], dns_module: TestDNSResolver)
      refute SafeURL.allowed?("http://includesecurity.com", schemes: ~w[ftp], dns_module: TestDNSResolver)
    end

    test "returns false for reserved ranges" do
      refute SafeURL.allowed?("http://0.0.0.0/")
      refute SafeURL.allowed?("http://10.0.0.1/")
      refute SafeURL.allowed?("http://127.0.0.1/")
      refute SafeURL.allowed?("http://169.254.9.1/")
      refute SafeURL.allowed?("http://192.168.1.1/")
    end

    test "returns true for reserved ranges if overridden" do
      opts = [block_reserved: false]

      assert SafeURL.allowed?("http://0.0.0.0/", opts)
      assert SafeURL.allowed?("http://10.0.0.1/", opts)
      assert SafeURL.allowed?("http://127.0.0.1/", opts)
      assert SafeURL.allowed?("http://169.254.9.1/", opts)
      assert SafeURL.allowed?("http://192.168.1.1/", opts)
    end

    test "blocking custom IP ranges" do
      opts = [blocklist: ["5.5.0.0/16", "100.0.0.0/24"], dns_module: TestDNSResolver]

      assert SafeURL.allowed?("http://includesecurity.com", opts)
      assert SafeURL.allowed?("http://3.3.3.3", opts)
      refute SafeURL.allowed?("http://5.5.5.5", opts)
      refute SafeURL.allowed?("http://100.0.0.50", opts)
    end

    test "only allows IPs in the allowlist when present" do
      opts = [allowlist: ["10.0.0.0/24"], dns_module: TestDNSResolver]

      assert SafeURL.allowed?("http://10.0.0.1/", opts)
      refute SafeURL.allowed?("http://72.254.45.178", opts)
      refute SafeURL.allowed?("https://includesecurity.com", opts)
    end
  end
end
