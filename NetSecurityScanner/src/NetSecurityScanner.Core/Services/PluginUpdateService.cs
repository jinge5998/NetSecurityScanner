using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 插件自动更新检测服务（v3-T10）。
  /// 对比本地已安装插件与市场插件的 SemVer 版本，生成"可更新插件"列表，
  /// 并提供后台定时轮询能力。
  /// </summary>
  public class PluginUpdateService
  {
    private readonly Func<IEnumerable<Plugin>> _marketFetcher;
    private readonly Func<IEnumerable<Plugin>> _installedFetcher;
    private CancellationTokenSource? _cts;
    private Thread? _workerThread;

    /// <summary>
    /// 构造插件更新服务。
    /// </summary>
    /// <param name="marketFetcher">返回市场插件列表的回调</param>
    /// <param name="installedFetcher">返回已安装插件列表的回调</param>
    public PluginUpdateService(
        Func<IEnumerable<Plugin>> marketFetcher,
        Func<IEnumerable<Plugin>> installedFetcher)
    {
      _marketFetcher = marketFetcher ?? throw new ArgumentNullException(nameof(marketFetcher));
      _installedFetcher = installedFetcher ?? throw new ArgumentNullException(nameof(installedFetcher));
    }

    /// <summary>
    /// 对比 installed 与 market，返回可更新插件（market 版本 &gt; installed 版本）。
    /// </summary>
    public List<Plugin> CheckUpdates(IEnumerable<Plugin> installed, IEnumerable<Plugin> market)
    {
      var updates = new List<Plugin>();
      if (installed == null || market == null) return updates;

      var installedList = installed as IList<Plugin> ?? installed.ToList();
      var marketList = market as IList<Plugin> ?? market.ToList();

      foreach (var m in marketList)
      {
        if (string.IsNullOrEmpty(m?.Id)) continue;
        var local = installedList.FirstOrDefault(p => p.Id == m.Id);
        if (local == null) continue; // 未安装的不算"可更新"
        try
        {
          if (SemVer.Compare(m.Version, local.Version) > 0)
          {
            m.HasUpdate = true;
            m.LastUpdated = DateTime.Now;
            updates.Add(m);
          }
        }
        catch
        {
          // 版本号解析失败时跳过该插件
        }
      }
      return updates;
    }

    /// <summary>
    /// 启动后台定时检查。
    /// 启动后立即跑一次，之后每隔 interval 跑一次。
    /// 多次调用只会保留最后一个 Worker。
    /// </summary>
    public void StartBackgroundCheck(TimeSpan interval, Action<List<Plugin>> onUpdate)
    {
      StopBackgroundCheck();
      if (onUpdate == null) throw new ArgumentNullException(nameof(onUpdate));
      if (interval <= TimeSpan.Zero) interval = TimeSpan.FromHours(1);

      _cts = new CancellationTokenSource();
      var token = _cts.Token;
      _workerThread = new Thread(() =>
      {
        while (!token.IsCancellationRequested)
        {
          try
          {
            var updates = CheckUpdates(_installedFetcher(), _marketFetcher());
            onUpdate(updates);
          }
          catch
          {
            // 单次失败不终止后台轮询
          }
          // 简单可被取消的 sleep
          int slept = 0;
          int stepMs = 500;
          int totalMs = (int)interval.TotalMilliseconds;
          while (slept < totalMs && !token.IsCancellationRequested)
          {
            Thread.Sleep(Math.Min(stepMs, totalMs - slept));
            slept += stepMs;
          }
        }
      })
      {
        IsBackground = true,
        Name = "PluginUpdateService.Worker"
      };
      _workerThread.Start();
    }

    /// <summary>
    /// 停止后台检查线程。
    /// </summary>
    public void StopBackgroundCheck()
    {
      try
      {
        _cts?.Cancel();
        _workerThread?.Join(TimeSpan.FromSeconds(2));
      }
      catch { }
      finally
      {
        _cts?.Dispose();
        _cts = null;
        _workerThread = null;
      }
    }
  }
}
