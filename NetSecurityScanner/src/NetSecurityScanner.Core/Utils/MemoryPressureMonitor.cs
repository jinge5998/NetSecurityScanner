using System;
using System.Runtime;
using System.Diagnostics;

namespace NetSecurityScanner.Utils
{
  public class MemoryPressureMonitor : IDisposable
  {
    private readonly int _warningThresholdMb;
    private readonly int _criticalThresholdMb;
    private readonly double _warningGcRatio;
    private long _lastGcTotalMemory;
    private int _consecutiveHighPressureReadings;
    private bool _disposed;

    public MemoryPressureMonitor(int warningThresholdMb = 512, int criticalThresholdMb = 1024, double warningGcRatio = 0.85)
    {
      _warningThresholdMb = warningThresholdMb;
      _criticalThresholdMb = criticalThresholdMb;
      _warningGcRatio = warningGcRatio;
      _lastGcTotalMemory = GC.GetTotalMemory(false);
    }

    public bool IsHighPressure()
    {
      var currentMemory = GC.GetTotalMemory(false);
      var currentMemoryMb = currentMemory / (1024.0 * 1024.0);

      if (currentMemoryMb > _criticalThresholdMb)
      {
        _consecutiveHighPressureReadings++;
        return true;
      }

      if (currentMemoryMb > _warningThresholdMb)
      {
        _consecutiveHighPressureReadings++;
        if (_consecutiveHighPressureReadings >= 3)
          return true;
      }
      else
      {
        _consecutiveHighPressureReadings = 0;
      }

      if (_consecutiveHighPressureReadings >= 5)
        return true;

      return false;
    }

    public double GetCurrentMemoryMb()
    {
      return GC.GetTotalMemory(false) / (1024.0 * 1024.0);
    }

    public int GetRecommendedConcurrency(int baseConcurrency)
    {
      if (IsHighPressure())
      {
        return Math.Max(2, baseConcurrency / 2);
      }

      var memoryMb = GetCurrentMemoryMb();
      if (memoryMb > _warningThresholdMb * 0.75)
      {
        return Math.Max(2, (int)(baseConcurrency * 0.7));
      }

      return baseConcurrency;
    }

    public void TriggerGcIfNeeded()
    {
      var currentMemory = GC.GetTotalMemory(false);
      var currentMemoryMb = currentMemory / (1024.0 * 1024.0);

      if (currentMemoryMb > _warningThresholdMb)
      {
        GC.Collect(2, GCCollectionMode.Optimized, false);
        GC.WaitForPendingFinalizers();
        GC.Collect(2, GCCollectionMode.Optimized, false);
      }
      else if (currentMemoryMb > _warningThresholdMb * 0.5)
      {
        GC.Collect(1, GCCollectionMode.Optimized, false);
      }
    }

    public static long GetProcessMemoryMb()
    {
      using var process = Process.GetCurrentProcess();
      return process.WorkingSet64 / (1024 * 1024);
    }

    public void Dispose()
    {
      if (!_disposed)
      {
        _disposed = true;
      }
    }
  }
}