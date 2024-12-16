defmodule SafeURLTest do
  use ExUnit.Case

  defmodule TestDNSResolver do
    @behaviour SafeURL.DNSResolver

    @impl true
    def resolve(_domain), do: {:ok, [{192, 0, 78, 24}]}
  end

  describe "validate/2?" do
    test "returns true for only allowed schemes" do
      opts = [dns_module: TestDNSResolver]
      assert :ok = SafeURL.validate("http://includesecurity.com", opts)
      assert :ok = SafeURL.validate("https://includesecurity.com", opts)
      assert {:error, :unsafe_scheme} = SafeURL.validate("ftp://includesecurity.com", opts)

      opts = [schemes: ~w[ftp], dns_module: TestDNSResolver]
      assert :ok = SafeURL.validate("ftp://includesecurity.com", opts)
      assert {:error, :unsafe_scheme} = SafeURL.validate("http://includesecurity.com", opts)
    end

    test "returns false for reserved ranges" do
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://0.0.0.0/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://10.0.0.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://127.0.0.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://169.254.9.1/")
      assert {:error, :unsafe_reserved} = SafeURL.validate("http://192.168.1.1/")
    end

    test "returns true for reserved ranges if overridden" do
      opts = [block_reserved: false]

      assert :ok = SafeURL.validate("http://0.0.0.0/", opts)
      assert :ok = SafeURL.validate("http://10.0.0.1/", opts)
      assert :ok = SafeURL.validate("http://127.0.0.1/", opts)
      assert :ok = SafeURL.validate("http://169.254.9.1/", opts)
      assert :ok = SafeURL.validate("http://192.168.1.1/", opts)
    end

    test "blocking custom IP ranges" do
      opts = [blocklist: ["5.5.0.0/16", "100.0.0.0/24"], dns_module: TestDNSResolver]

      assert :ok = SafeURL.validate("http://includesecurity.com", opts)
      assert :ok = SafeURL.validate("http://3.3.3.3", opts)
      assert {:error, :unsafe_blocklist} = SafeURL.validate("http://5.5.5.5", opts)
      assert {:error, :unsafe_blocklist} = SafeURL.validate("http://100.0.0.50", opts)
    end

    test "only allows IPs in the allowlist when present" do
      opts = [allowlist: ["10.0.0.0/24"], dns_module: TestDNSResolver]

      assert :ok = SafeURL.validate("http://10.0.0.1/", opts)
      assert {:error, :unsafe_allowlist} = SafeURL.validate("http://72.254.45.178", opts)
      assert {:error, :unsafe_allowlist} = SafeURL.validate("https://includesecurity.com", opts)
    end

    test "detailed_errors can be switched off" do
      opts = [blocklist: ["5.5.0.0/16"], dns_module: TestDNSResolver, detailed_error: false]
      assert {:error, :restricted} = SafeURL.validate("ftp://includesecurity.com", opts)
      assert {:error, :restricted} = SafeURL.validate("http://5.5.5.5", opts)
      assert {:error, :restricted} = SafeURL.validate("http://0.0.0.0/", opts)
    end
  end
end
