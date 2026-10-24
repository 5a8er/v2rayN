namespace ServiceLib.Manager;

/// <summary>
/// Core process processing class
/// </summary>
public class CoreManager
{
    private static readonly Lazy<CoreManager> _instance = new(() => new());
    public static CoreManager Instance => _instance.Value;
    private Config _config;

    /// <summary>Context of the last main core load; its outbound tag map lets the kill switch pin a carrier.</summary>
    public CoreConfigContext? RunningContext { get; private set; }

    [SupportedOSPlatform("windows")]
    private WindowsJobService? _processJob;

    private ProcessService? _processService;
    private ProcessService? _processPreService;
    private bool _linuxSudo = false;

    // Loads and stops run one at a time: a reload (e.g. after a subscription update) racing the
    // exit's stop used to lose track of the freshly started core and leave it orphaned.
    private readonly SemaphoreSlim _coreLock = new(1, 1);
    private bool _exiting;
    private Func<bool, string, Task>? _updateFunc;
    private const string _tag = "CoreHandler";

    public async Task Init(Config config, Func<bool, string, Task> updateFunc)
    {
        _config = config;
        _updateFunc = updateFunc;

        //Copy the bin folder to the storage location (for init)
        if (Environment.GetEnvironmentVariable(Global.LocalAppData) == "1")
        {
            var fromPath = Utils.GetBaseDirectory("bin");
            var toPath = Utils.GetBinPath("");
            if (fromPath != toPath)
            {
                FileUtils.CopyDirectory(fromPath, toPath, true, false);
            }
        }

        if (Utils.IsNonWindows())
        {
            var coreInfo = CoreInfoManager.Instance.GetCoreInfo();
            foreach (var it in coreInfo)
            {
                if (it.CoreType == ECoreType.v2rayN)
                {
                    if (Utils.UpgradeAppExists(out var upgradeFileName))
                    {
                        await Utils.SetLinuxChmod(upgradeFileName);
                    }
                    continue;
                }

                foreach (var name in it.CoreExes)
                {
                    var exe = Utils.GetBinPath(Utils.GetExeName(name), it.CoreType.ToString());
                    if (File.Exists(exe))
                    {
                        await Utils.SetLinuxChmod(exe);
                    }
                }
            }
        }
    }

    /// <param name="mainContext">Resolved main context (with pre-socks ports already merged if applicable).</param>
    /// <param name="preContext">Optional pre-socks context passed to <see cref="CoreStartPreService"/>.</param>
    public async Task LoadCore(CoreConfigContext? mainContext, CoreConfigContext? preContext)
    {
        if (mainContext == null)
        {
            await UpdateFunc(false, ResUI.CheckServerSettings);
            return;
        }

        await _coreLock.WaitAsync();
        try
        {
            if (_exiting)
            {
                return;
            }
            await LoadCoreLocked(mainContext, preContext);
        }
        finally
        {
            _coreLock.Release();
        }
    }

    private async Task LoadCoreLocked(CoreConfigContext mainContext, CoreConfigContext? preContext)
    {

        var node = mainContext.Node;
        var fileName = Utils.GetBinConfigPath(Global.CoreConfigFileName);
        var result = await CoreConfigHandler.GenerateClientConfig(mainContext, fileName);
        if (result.Success != true)
        {
            await UpdateFunc(true, result.Msg);
            return;
        }

        await UpdateFunc(false, $"{node.GetSummary()}");
        await UpdateFunc(false, $"{Utils.GetRuntimeInfo()}");
        await UpdateFunc(false, string.Format(ResUI.StartService, DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")));
        await CoreStopLocked();
        await Task.Delay(100);
        RunningContext = mainContext;

        // The firewall must be in place before any core can open a connection
        if (_config.KillSwitchItem.Enabled && KillSwitchManager.IsSupported)
        {
            var killSwitchError = await KillSwitchManager.Instance.ApplyAsync(mainContext);
            if (killSwitchError != null)
            {
                // Fail closed: without the matching firewall, run nothing rather than risk a leak
                await UpdateFunc(true, killSwitchError);
                return;
            }
        }

        if (Utils.IsWindows() && (mainContext?.IsTunEnabled == true || preContext?.IsTunEnabled == true))
        {
            await Task.Delay(100);
            await WindowsUtils.RemoveTunDevice();
        }

        await CoreStart(mainContext);
        await WaitForProxyPort(preContext);
        await CoreStartPreService(preContext);
        await RestartMainCoreAfterTun(mainContext, preContext);

        AppManager.Instance.RunningCoreType = preContext?.RunCoreType ?? mainContext.RunCoreType;

        if (_processService != null)
        {
            await UpdateFunc(true, $"{node.GetSummary()}");
        }
    }

    public async Task<ProcessService?> LoadCoreConfigSpeedtest(List<ServerTestItem> selecteds)
    {
        var coreType = selecteds.FirstOrDefault()?.CoreType == ECoreType.sing_box ? ECoreType.sing_box : ECoreType.Xray;
        var fileName = string.Format(Global.CoreSpeedtestConfigFileName, Utils.GetGuid(false));
        var configPath = Utils.GetBinConfigPath(fileName);
        var result = await CoreConfigHandler.GenerateClientSpeedtestConfig(_config, configPath, selecteds, coreType);
        await UpdateFunc(false, result.Msg);
        if (result.Success != true)
        {
            return null;
        }

        await UpdateFunc(false, string.Format(ResUI.StartService, DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss")));
        await UpdateFunc(false, configPath);

        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(coreType);
        return await RunProcess(coreInfo, fileName, true, false);
    }

    public async Task<ProcessService?> LoadCoreConfigSpeedtest(ServerTestItem testItem)
    {
        var node = await AppManager.Instance.GetProfileItem(testItem.IndexId);
        if (node is null)
        {
            return null;
        }

        var fileName = string.Format(Global.CoreSpeedtestConfigFileName, Utils.GetGuid(false));
        var configPath = Utils.GetBinConfigPath(fileName);
        var (context, _) = await CoreConfigContextBuilder.Build(_config, node);
        var result = await CoreConfigHandler.GenerateClientSpeedtestConfig(_config, context, testItem, configPath);
        if (result.Success != true)
        {
            return null;
        }

        var coreType = context.RunCoreType;
        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(coreType);
        return await RunProcess(coreInfo, fileName, true, false);
    }

    /// <param name="forExit">The app is closing: also refuse any reload still waiting to run.</param>
    public async Task CoreStop(bool forExit = false)
    {
        await _coreLock.WaitAsync();
        try
        {
            _exiting |= forExit;
            await CoreStopLocked();
        }
        finally
        {
            _coreLock.Release();
        }
    }

    private async Task CoreStopLocked()
    {
        try
        {
            if (_linuxSudo)
            {
                await CoreAdminManager.Instance.KillProcessAsLinuxSudo();
                _linuxSudo = false;
            }

            var process = _processService;
            _processService = null;
            if (process != null)
            {
                await process.StopAsync();
                process.Dispose();
            }

            var preProcess = _processPreService;
            _processPreService = null;
            if (preProcess != null)
            {
                await preProcess.StopAsync();
                preProcess.Dispose();
            }
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
        }
    }

    #region Private

    private async Task CoreStart(CoreConfigContext context)
    {
        var node = context.Node;
        var coreType = AppManager.Instance.GetCoreType(node, node.ConfigType);
        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(coreType);

        var displayLog = node.ConfigType != EConfigType.Custom || node.DisplayLog;
        var proc = await RunProcess(coreInfo, Global.CoreConfigFileName, displayLog, true, context.IsTunEnabled);
        if (proc is null)
        {
            return;
        }
        _processService = proc;
    }

    private async Task CoreStartPreService(CoreConfigContext? preContext)
    {
        if (_processService is { HasExited: false } && preContext != null)
        {
            var preCoreType = preContext?.Node?.CoreType ?? ECoreType.sing_box;
            var fileName = Utils.GetBinConfigPath(Global.CorePreConfigFileName);
            var result = await CoreConfigHandler.GenerateClientConfig(preContext, fileName);
            if (result.Success)
            {
                var coreInfo = CoreInfoManager.Instance.GetCoreInfo(preCoreType);
                var proc = await RunProcess(coreInfo, Global.CorePreConfigFileName, true, true, preContext.IsTunEnabled);
                if (proc is null)
                {
                    return;
                }
                _processPreService = proc;
            }
        }
    }

    private async Task RestartMainCoreAfterTun(CoreConfigContext mainContext, CoreConfigContext? preContext)
    {
        if (!mainContext.RestartAfterTun
            || preContext?.IsTunEnabled != true
            || mainContext.IsTunEnabled
            || _processPreService is not { HasExited: false }
            || _processService is null)
        {
            return;
        }

        await WaitForTunDevice();

        await _processService.StopAsync();
        _processService.Dispose();
        _processService = null;
        await CoreStart(mainContext);
        await UpdateFunc(false, "Restarted core after TUN came up (WireGuard chain)");
    }

    private static async Task WaitForTunDevice()
    {
        // The interface name is only fixed on Linux; elsewhere just give the routes a moment.
        if (!Utils.IsLinux())
        {
            await Task.Delay(1000);
            return;
        }

        for (var i = 0; i < 100; i++)
        {
            if (NetworkInterface.GetAllNetworkInterfaces().Any(n => n.Name == "singbox_tun"))
            {
                break;
            }
            await Task.Delay(100);
        }
        // auto_route installs the rules right after the device appears
        await Task.Delay(500);
    }

    private async Task UpdateFunc(bool notify, string msg)
    {
        await _updateFunc?.Invoke(notify, msg);
    }

    private static async Task WaitForProxyPort(CoreConfigContext? preContext)
    {
        if (preContext is null)
        {
            return;
        }
        if (!preContext.IsTunEnabled)
        {
            return;
        }

        using var rootCts = new CancellationTokenSource(Global.LocalFetch);
        var rootToken = rootCts.Token;

        var port = preContext.Node.Port;
        // SOCKS5 client greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth)
        ReadOnlyMemory<byte> greeting = new byte[] { 0x05, 0x01, 0x00 };
        var buf = new byte[2];

        while (!rootToken.IsCancellationRequested)
        {
            using var tcp = new TcpClient();
            using var attemptCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(rootToken, attemptCts.Token);
            var linkedToken = linkedCts.Token;
            try
            {
                await tcp.ConnectAsync(Global.Loopback, port, linkedToken);
                var stream = tcp.GetStream();

                await stream.WriteAsync(greeting, linkedToken);

                var read = await stream.ReadAsync(buf.AsMemory(0, 2), linkedToken);

                // Server selection: VER=5, METHOD=0x00 — proxy is fully ready
                if (read == 2 && buf[0] == 0x05)
                {
                    return;
                }
            }
            catch (OperationCanceledException)
            {
                if (!rootToken.IsCancellationRequested)
                {
                    continue;
                }
                Logging.SaveLog($"WaitForProxyPort Timeout waiting for proxy port {port} to be ready.");
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                // Connection refused, proxy not ready yet, wait 50ms before retrying
                try
                {
                    await Task.Delay(50, rootToken);
                }
                catch (OperationCanceledException)
                {
                    Logging.SaveLog($"WaitForProxyPort Timeout waiting for proxy port {port} to be ready.");
                    return;
                }
            }
            catch
            {
                // Ignore other exceptions and continue
            }
        }
    }

    #endregion Private

    #region Process

    /// <summary>
    ///     Decides whether a core launch must be elevated on non-Windows platforms.
    ///     The TUN state comes from the immutable <see cref="CoreConfigContext" /> snapshot that
    ///     generated the config, never from the live mutable config: the generated config and the
    ///     launch mode must always agree, even if TUN is toggled while a reload is in flight.
    /// </summary>
    public static bool ShouldRunAsSudo(bool isTunLaunch, ECoreType? coreType, bool isNonWindows)
    {
        return isTunLaunch
            && coreType is ECoreType.sing_box or ECoreType.mihomo or ECoreType.Xray
            && isNonWindows;
    }

    private async Task<ProcessService?> RunProcess(CoreInfo? coreInfo, string configPath, bool displayLog, bool mayNeedSudo, bool isTunLaunch = false)
    {
        var fileName = CoreInfoManager.Instance.GetCoreExecFile(coreInfo, out var msg);
        if (fileName.IsNullOrEmpty())
        {
            await UpdateFunc(false, msg);
            return null;
        }

        try
        {
            if (mayNeedSudo
                && ShouldRunAsSudo(isTunLaunch, coreInfo.CoreType, Utils.IsNonWindows()))
            {
                _linuxSudo = true;
                await CoreAdminManager.Instance.Init(_config, _updateFunc);
                return await CoreAdminManager.Instance.RunProcessAsLinuxSudo(fileName, coreInfo, configPath);
            }

            return await RunProcessNormal(fileName, coreInfo, configPath, displayLog);
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            await UpdateFunc(mayNeedSudo, ex.Message);
            return null;
        }
    }

    private async Task<ProcessService?> RunProcessNormal(string fileName, CoreInfo? coreInfo, string configPath, bool displayLog)
    {
        var environmentVars = new Dictionary<string, string>();
        foreach (var kv in coreInfo.Environment)
        {
            environmentVars[kv.Key] = string.Format(kv.Value, coreInfo.AbsolutePath ? Utils.GetBinConfigPath(configPath).AppendQuotes() : configPath);
        }

        var procService = new ProcessService(
            fileName: fileName,
            arguments: string.Format(coreInfo.Arguments, coreInfo.AbsolutePath ? Utils.GetBinConfigPath(configPath).AppendQuotes() : configPath),
            workingDirectory: Utils.GetBinConfigPath(),
            displayLog: displayLog,
            redirectInput: false,
            environmentVars: environmentVars,
            updateFunc: _updateFunc
        );

        await procService.StartAsync();

        await Task.Delay(100);

        if (procService is null or { HasExited: true })
        {
            throw new Exception(ResUI.FailedToRunCore);
        }
        AddProcessJob(procService.Handle);

        return procService;
    }

    private void AddProcessJob(nint processHandle)
    {
        if (Utils.IsWindows())
        {
            _processJob ??= new();
            try
            {
                _processJob?.AddProcess(processHandle);
            }
            catch { }
        }
    }

    #endregion Process
}
