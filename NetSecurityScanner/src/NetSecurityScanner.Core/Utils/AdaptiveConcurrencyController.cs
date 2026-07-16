using System;
using System.Threading;

namespace NetSecurityScanner.Utils
{
  public class AdaptiveConcurrencyController : IDisposable
  {
    private readonly int _baseConcurrency;
    private readonly int _minConcurrency;
    private readonly int _maxConcurrency;
    private readonly MemoryPressureMonitor _memoryMonitor;
    private int _currentConcurrency;
    private readonly object _lock = new();
    private bool _disposed;

    public int CurrentConcurrency
    {
      get { lock (_lock) return _currentConcurrency; }
    }

    public AdaptiveConcurrencyController(int baseConcurrency = 10, int? minConcurrency = null, int? maxConcurrency = null, int? warningThresholdMb = null)
    {
      _baseConcurrency = Math.Max(1, baseConcurrency);
      _minConcurrency = Math.Max(1, minConcurrency ?? 2);
      _maxConcurrency = Math.Min(Environment.ProcessorCount * 4, maxConcurrency ?? Environment.ProcessorCount * 2);
      _currentConcurrency = _baseConcurrency;
      _memoryMonitor = new MemoryPressureMonitor(
          warningThresholdMb: warningThresholdMb ?? 512,
          criticalThresholdMb: warningThresholdMb.HasValue ? warningThresholdMb.Value * 2 : 1024
      );
    }

    public int GetOptimalConcurrency()
    {
      lock (_lock)
      {
        var memRecommended = _memoryMonitor.GetRecommendedConcurrency(_baseConcurrency);
        _currentConcurrency = Math.Clamp(memRecommended, _minConcurrency, _maxConcurrency);
        return _currentConcurrency;
      }
    }

    public int AdjustConcurrency(int currentConcurrency)
    {
      lock (_lock)
      {
        if (_memoryMonitor.IsHighPressure())
        {
          _currentConcurrency = Math.Max(_minConcurrency, currentConcurrency / 2);
        }
        else
        {
          var memMb = _memoryMonitor.GetCurrentMemoryMb();
          if (memMb < 256)
          {
            _currentConcurrency = Math.Min(_maxConcurrency, currentConcurrency + 2);
          }
          else
          {
            _currentConcurrency = _memoryMonitor.GetRecommendedConcurrency(_baseConcurrency);
          }
        }

        _currentConcurrency = Math.Clamp(_currentConcurrency, _minConcurrency, _maxConcurrency);
        return _currentConcurrency;
      }
    }

    public void CheckAndTriggerGc()
    {
      _memoryMonitor.TriggerGcIfNeeded();
    }

    public void Reset()
    {
      lock (_lock)
      {
        _currentConcurrency = _baseConcurrency;
      }
    }

    public void Dispose()
    {
      if (!_disposed)
      {
        _memoryMonitor.Dispose();
        _disposed = true;
      }
    }
  }
}