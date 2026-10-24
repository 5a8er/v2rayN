namespace ServiceLib.Models.CoreConfigs;

public record CoreConfigContext
{
    public required ProfileItem Node { get; init; }
    public required ECoreType RunCoreType { get; init; }
    public RoutingItem? RoutingItem { get; init; }
    public DNSItem? RawDnsItem { get; init; }
    public SimpleDNSItem SimpleDnsItem { get; init; } = new();
    public Dictionary<string, ProfileItem> AllProxiesMap { get; init; } = new();
    public Config AppConfig { get; init; } = new();
    public FullConfigTemplateItem? FullConfigTemplate { get; init; } = new();

    public Dictionary<string, string> CustomOutboundContent { get; init; } = new();

    // Test ServerTestItem Map
    public Dictionary<string, string> ServerTestItemMap { get; init; } = new();

    // TUN Compatibility
    public bool IsTunEnabled { get; init; } = false;
    public HashSet<string> ProtectDomainList { get; init; } = [];
    // Typically, it is the core of the outbound chain
    public HashSet<ECoreType> ProtectCoreTypeList { get; init; } = [];

    public bool IsWindows { get; init; }
    public bool IsMacOS { get; init; }
    public bool IsLinux { get; init; }

    // Defaults to true so that a context built without this flag keeps routing IPv6 into the
    // tunnel; only a positive detection of the host having no global IPv6 address turns it off.
    public bool HasGlobalIPv6Address { get; init; } = true;

    // Generation Context
    public Dictionary<object, string> CustomOutboundMap { get; init; } = new();

    // Groups reached through a loopback outbound instead of cloning the downstream chain;
    // each entry needs an observatory, a balancer and an inboundTag routing rule.
    public List<LoopbackRoute> LoopbackRoutes { get; init; } = [];
}

public record LoopbackRoute(string InboundTag, string Selector, EMultipleLoad MultipleLoad);
