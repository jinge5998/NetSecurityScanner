using System;
using System.Collections.Generic;

namespace NetSecurityScanner.Core
{
  /// <summary>
  /// 简化的 5 字段 Cron 表达式解析器（v3-T3）。
  /// 字段顺序：<c>分 时 日 月 周</c>，与 Linux crontab 一致。
  /// 支持 <c>*</c>、<c>n</c>、<c>n-m</c>、<c>n,m</c>、<c>*/k</c>。
  /// 周字段：0 或 7 表示周日，1=周一 ... 6=周六。
  /// </summary>
  public class CronExpression
  {
    private readonly CronField _minute;
    private readonly CronField _hour;
    private readonly CronField _day;
    private readonly CronField _month;
    private readonly CronField _week;

    public CronExpression(string expression)
    {
      if (string.IsNullOrWhiteSpace(expression))
        throw new ArgumentException("Cron 表达式不能为空", nameof(expression));

      var parts = expression.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
      if (parts.Length != 5)
        throw new ArgumentException($"Cron 表达式必须包含 5 个字段（分 时 日 月 周），当前: {parts.Length}", nameof(expression));

      _minute = new CronField(parts[0], 0, 59);
      _hour = new CronField(parts[1], 0, 23);
      _day = new CronField(parts[2], 1, 31);
      _month = new CronField(parts[3], 1, 12);
      _week = new CronField(parts[4], 0, 7); // 0 和 7 都视为周日
    }

    /// <summary>
    /// 返回严格大于 <paramref name="from"/> 的下一次触发时间。
    /// 如果在合理窗口内（默认 4 年）找不到，返回 null。
    /// </summary>
    public DateTime? NextOccurrence(DateTime from)
    {
      var current = new DateTime(from.Year, from.Month, from.Day, from.Hour, from.Minute, 0).AddMinutes(1);
      var end = current.AddYears(4);
      while (current < end)
      {
        if (_month.Matches(current.Month))
        {
          if (_day.Matches(current.Day) && _week.Matches((int)current.DayOfWeek))
          {
            if (_hour.Matches(current.Hour) && _minute.Matches(current.Minute))
            {
              return current;
            }
          }
        }
        current = current.AddMinutes(1);
      }
      return null;
    }

    public static DateTime? NextOccurrence(string expression, DateTime from)
    {
      if (string.IsNullOrWhiteSpace(expression)) return null;
      try
      {
        return new CronExpression(expression).NextOccurrence(from);
      }
      catch
      {
        return null;
      }
    }

    private sealed class CronField
    {
      private readonly HashSet<int> _values = new();

      public CronField(string raw, int min, int max)
      {
        foreach (var part in raw.Split(','))
        {
          var token = part.Trim();
          if (string.IsNullOrEmpty(token)) continue;

          int step = 1;
          var stepSplit = token.Split('/');
          if (stepSplit.Length == 2)
          {
            if (!int.TryParse(stepSplit[1], out step) || step <= 0)
              throw new ArgumentException($"非法步长: {token}");
            token = stepSplit[0];
          }

          int from, to;
          if (token == "*")
          {
            from = min;
            to = max;
          }
          else if (token.Contains('-'))
          {
            var rangeParts = token.Split('-');
            if (rangeParts.Length != 2 ||
                !int.TryParse(rangeParts[0], out from) ||
                !int.TryParse(rangeParts[1], out to))
              throw new ArgumentException($"非法区间: {token}");
          }
          else
          {
            if (!int.TryParse(token, out from))
              throw new ArgumentException($"非法值: {token}");
            to = stepSplit.Length == 2 ? max : from;
          }

          if (from < min || to > max || from > to)
            throw new ArgumentException($"值越界或区间错误: {part}（允许 {min}-{max}）");

          for (var v = from; v <= to; v += step)
          {
            _values.Add(v == 7 && max == 7 ? 0 : v); // 周字段 7 -> 0
          }
        }

        if (_values.Count == 0)
          throw new ArgumentException("字段解析后为空");
      }

      public bool Matches(int value) => _values.Contains(value);
    }
  }
}
