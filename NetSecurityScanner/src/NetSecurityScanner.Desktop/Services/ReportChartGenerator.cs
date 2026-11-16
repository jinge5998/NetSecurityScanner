using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;

namespace NetSecurityScanner
{
    public static class ReportChartGenerator
    {
        private static readonly System.Drawing.Color DeepBlue = System.Drawing.Color.FromArgb(30, 58, 95);
        private static readonly System.Drawing.Color MidBlue = System.Drawing.Color.FromArgb(37, 99, 235);
        private static readonly System.Drawing.Color LightBg = System.Drawing.Color.FromArgb(248, 250, 252);
        private static readonly System.Drawing.Color TextDark = System.Drawing.Color.FromArgb(30, 41, 59);
        private static readonly System.Drawing.Color TextGray = System.Drawing.Color.FromArgb(100, 116, 139);
        private static readonly System.Drawing.Color White = System.Drawing.Color.White;

        public static byte[] GenerateRiskPieChart(List<(string Label, int Count, System.Drawing.Color Color)> data)
        {
            try
            {
                int size = 400;
                int padding = 30;
                int chartSize = size - padding * 2;
                int centerX = size / 2;
                int centerY = size / 2 + 10;
                int radius = 110;
                int legendX = size - 170;
                int legendY = 60;

                using var bmp = new Bitmap(size, size);
                using var g = Graphics.FromImage(bmp);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.AntiAlias;
                g.Clear(White);

                using var titleFont = new Font("Microsoft YaHei", 14, FontStyle.Bold);
                g.DrawString("漏洞风险分布", titleFont, new SolidBrush(DeepBlue), padding, 15);

                g.DrawLine(new Pen(System.Drawing.Color.FromArgb(226, 232, 240), 1), padding, 42, size - padding, 42);

                var total = data.Sum(d => d.Count);
                if (total == 0) return null;

                float startAngle = -90;
                float topY = 45;

                using var bgRect = new SolidBrush(System.Drawing.Color.FromArgb(250, 250, 252));
                g.FillRectangle(bgRect, centerX - radius - 15, topY, radius * 2 + 30, radius * 2 + 15);

                using var shadowPen = new Pen(System.Drawing.Color.FromArgb(200, 210, 220), 1);
                g.DrawEllipse(shadowPen, centerX - radius, topY, radius * 2, radius * 2);

                foreach (var item in data)
                {
                    var sweepAngle = (float)item.Count / total * 360;
                    if (sweepAngle < 1) sweepAngle = 1;

                    using var brush = new SolidBrush(item.Color);
                    g.FillPie(brush, centerX - radius, topY, radius * 2, radius * 2, startAngle, sweepAngle);

                    using var whitePen = new Pen(White, 2.5f);
                    g.DrawPie(whitePen, centerX - radius, topY, radius * 2, radius * 2, startAngle, sweepAngle);

                    if (sweepAngle > 18)
                    {
                        var midAngle = startAngle + sweepAngle / 2;
                        var labelRadius = radius * 0.63f;
                        var labelX = centerX + (float)(labelRadius * Math.Cos(midAngle * Math.PI / 180));
                        var labelY = topY + radius + (float)(labelRadius * Math.Sin(midAngle * Math.PI / 180));
                        var pct = (double)item.Count / total * 100;
                        var labelStr = $"{pct:F0}%";
                        using var labelFont = new Font("Microsoft YaHei", 12, FontStyle.Bold);
                        var labelSize = g.MeasureString(labelStr, labelFont);
                        g.DrawString(labelStr, labelFont, new SolidBrush(White),
                            labelX - labelSize.Width / 2, labelY - labelSize.Height / 2);
                    }

                    startAngle += sweepAngle;
                }

                using var innerBrush = new SolidBrush(White);
                g.FillEllipse(innerBrush, centerX - 38, topY + radius - 38, 76, 76);
                var totalFont = new Font("Microsoft YaHei", 16, FontStyle.Bold);
                var totalStr = total.ToString();
                var totalSize = g.MeasureString(totalStr, totalFont);
                g.DrawString(totalStr, totalFont, new SolidBrush(DeepBlue),
                    centerX - totalSize.Width / 2, topY + radius - totalSize.Height / 2 - 2);
                var unitFont = new Font("Microsoft YaHei", 9, FontStyle.Regular);
                g.DrawString("总计", unitFont, new SolidBrush(TextGray),
                    centerX - g.MeasureString("总计", unitFont).Width / 2, topY + radius + 14);

                using var legendFont = new Font("Microsoft YaHei", 10, FontStyle.Regular);
                int ly = legendY;
                foreach (var item in data)
                {
                    using var colorBrush = new SolidBrush(item.Color);
                    g.FillRectangle(colorBrush, legendX, ly, 14, 14);
                    g.DrawRectangle(new Pen(System.Drawing.Color.FromArgb(200, 200, 200), 0.5f), legendX, ly, 14, 14);

                    var pct = (double)item.Count / total * 100;
                    g.DrawString($"{item.Label}", legendFont, new SolidBrush(TextDark), legendX + 20, ly - 1);
                    g.DrawString($"{item.Count}个 ({pct:F1}%)", new Font("Microsoft YaHei", 9, FontStyle.Regular),
                        new SolidBrush(TextGray), legendX + 70, ly - 1);
                    ly += 26;
                }

                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                    return ms.ToArray();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ChartGen] 饼图生成失败: {ex.Message}");
                return null;
            }
        }

        public static byte[] GenerateRiskBarChart(List<(string Label, int Count, System.Drawing.Color Color)> data)
        {
            try
            {
                int width = 520;
                int height = 220;
                int padding = 40;
                int chartLeft = padding + 20;
                int chartTop = padding + 10;
                int chartWidth = width - chartLeft - padding;
                int chartHeight = height - chartTop - padding - 20;
                int barWidth = Math.Min(50, (chartWidth / data.Count) - 15);
                int barGap = chartWidth / data.Count;

                var maxVal = data.Max(d => d.Count);
                if (maxVal == 0) maxVal = 1;

                using var bmp = new Bitmap(width, height);
                using var g = Graphics.FromImage(bmp);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(White);

                using var gridPen = new Pen(System.Drawing.Color.FromArgb(230, 234, 240), 0.5f);
                for (int i = 0; i <= 4; i++)
                {
                    int y = chartTop + chartHeight * i / 4;
                    g.DrawLine(gridPen, chartLeft, y, chartLeft + chartWidth, y);
                    var val = maxVal * (4 - i) / 4;
                    using var gridFont = new Font("Microsoft YaHei", 8, FontStyle.Regular);
                    g.DrawString(val.ToString(), gridFont, new SolidBrush(TextGray), 2, y - 6);
                }

                var total = data.Sum(d => d.Count);
                for (int i = 0; i < data.Count; i++)
                {
                    int barH = (int)((double)data[i].Count / maxVal * chartHeight);
                    int x = chartLeft + barGap * i + (barGap - barWidth) / 2;
                    int y = chartTop + chartHeight - barH;

                    using var barBrush = new SolidBrush(data[i].Color);
                    g.FillRectangle(barBrush, x, y, barWidth, barH);

                    using var barPen = new Pen(System.Drawing.Color.FromArgb(255, 255, 255, 255), 1f);
                    g.DrawRectangle(barPen, x, y, barWidth, barH);

                    using var valFont = new Font("Microsoft YaHei", 9, FontStyle.Bold);
                    var valStr = data[i].Count.ToString();
                    var valSize = g.MeasureString(valStr, valFont);
                    g.DrawString(valStr, valFont, new SolidBrush(data[i].Color),
                        x + barWidth / 2 - valSize.Width / 2, y - 18);

                    using var labelFont = new Font("Microsoft YaHei", 9, FontStyle.Regular);
                    var labelSize = g.MeasureString(data[i].Label, labelFont);
                    g.DrawString(data[i].Label, labelFont, new SolidBrush(TextDark),
                        x + barWidth / 2 - labelSize.Width / 2, chartTop + chartHeight + 4);
                }

                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                    return ms.ToArray();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ChartGen] 柱状图生成失败: {ex.Message}");
                return null;
            }
        }

        public static byte[] GenerateRiskGaugeChart(string riskLevel, int score)
        {
            try
            {
                int size = 280;
                int centerX = size / 2;
                int centerY = size / 2;
                int arcRadius = 80;
                int arcThickness = 22;

                using var bmp = new Bitmap(size, size);
                using var g = Graphics.FromImage(bmp);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(White);

                using (var bgArcPen = new Pen(System.Drawing.Color.FromArgb(220, 225, 232), arcThickness))
                {
                    bgArcPen.StartCap = LineCap.Round;
                    bgArcPen.EndCap = LineCap.Round;
                    g.DrawArc(bgArcPen, centerX - arcRadius, centerY - arcRadius,
                        arcRadius * 2, arcRadius * 2, 180, 180);
                }

                var riskColor = System.Drawing.Color.FromArgb(5, 150, 105);
                if (riskLevel == "严重") riskColor = System.Drawing.Color.FromArgb(153, 27, 27);
                else if (riskLevel == "高") riskColor = System.Drawing.Color.FromArgb(194, 65, 12);
                else if (riskLevel == "中") riskColor = System.Drawing.Color.FromArgb(217, 119, 6);

                float sweep = Math.Min(180, (float)score / 100 * 180);
                using (var arcPen = new Pen(riskColor, arcThickness))
                {
                    arcPen.StartCap = LineCap.Round;
                    arcPen.EndCap = LineCap.Round;
                    g.DrawArc(arcPen, centerX - arcRadius, centerY - arcRadius,
                        arcRadius * 2, arcRadius * 2, 180, sweep);
                }

                using var levelFont = new Font("Microsoft YaHei", 20, FontStyle.Bold);
                var levelStr = riskLevel;
                var levelSize = g.MeasureString(levelStr, levelFont);
                g.DrawString(levelStr, levelFont, new SolidBrush(riskColor),
                    centerX - levelSize.Width / 2, centerY - levelSize.Height / 2);

                using var scoreFont = new Font("Microsoft YaHei", 13, FontStyle.Bold);
                var scoreStr = $"安全评分: {score}/100";
                var scoreSize = g.MeasureString(scoreStr, scoreFont);
                g.DrawString(scoreStr, scoreFont, new SolidBrush(TextGray),
                    centerX - scoreSize.Width / 2, centerY + 25);

                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                    return ms.ToArray();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ChartGen] 仪表盘生成失败: {ex.Message}");
                return null;
            }
        }

        public static byte[] GeneratePortServiceBarChart(List<(string Service, int Count)> data)
        {
            try
            {
                int width = 500;
                int height = 200;
                int chartLeft = 60;
                int chartTop = 15;
                int chartWidth = width - chartLeft - 20;
                int chartHeight = height - chartTop - 35;

                var maxVal = data.Max(d => d.Count);
                if (maxVal == 0) maxVal = 1;
                int barWidth = Math.Min(40, (chartWidth / data.Count) - 12);
                int barGap = chartWidth / data.Count;

                using var bmp = new Bitmap(width, height);
                using var g = Graphics.FromImage(bmp);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(White);

                var colors = new[] {
                    System.Drawing.Color.FromArgb(59, 130, 246),
                    System.Drawing.Color.FromArgb(16, 185, 129),
                    System.Drawing.Color.FromArgb(245, 158, 11),
                    System.Drawing.Color.FromArgb(239, 68, 68),
                    System.Drawing.Color.FromArgb(139, 92, 246),
                };

                using var gridPen = new Pen(System.Drawing.Color.FromArgb(230, 234, 240), 0.5f);
                for (int i = 0; i <= 4; i++)
                {
                    int y = chartTop + chartHeight * i / 4;
                    g.DrawLine(gridPen, chartLeft, y, chartLeft + chartWidth, y);
                    var val = maxVal * (4 - i) / 4;
                    using var gridFont = new Font("Microsoft YaHei", 8, FontStyle.Regular);
                    g.DrawString(val.ToString(), gridFont, new SolidBrush(TextGray), chartLeft - 22, y - 6);
                }

                for (int i = 0; i < data.Count; i++)
                {
                    int barH = (int)((double)data[i].Count / maxVal * chartHeight);
                    int x = chartLeft + barGap * i + (barGap - barWidth) / 2;
                    int y = chartTop + chartHeight - barH;

                    var color = colors[i % colors.Length];
                    using var barBrush = new SolidBrush(color);
                    g.FillRectangle(barBrush, x, y, barWidth, barH);

                    using var valFont = new Font("Microsoft YaHei", 8, FontStyle.Bold);
                    var valStr = data[i].Count.ToString();
                    var valSize = g.MeasureString(valStr, valFont);
                    g.DrawString(valStr, valFont, new SolidBrush(color), x + barWidth / 2 - valSize.Width / 2, y - 15);

                    using var labelFont = new Font("Microsoft YaHei", 8, FontStyle.Regular);
                    var svc = data[i].Service.Length > 6 ? data[i].Service.Substring(0, 6) : data[i].Service;
                    var labelSize = g.MeasureString(svc, labelFont);
                    g.DrawString(svc, labelFont, new SolidBrush(TextDark),
                        x + barWidth / 2 - labelSize.Width / 2, chartTop + chartHeight + 3);
                }

                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                    return ms.ToArray();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ChartGen] 服务柱状图生成失败: {ex.Message}");
                return null;
            }
        }

        public static byte[] GenerateComplianceRadarChart(List<(string Standard, int Score)> data)
        {
            try
            {
                int size = 350;
                int cx = size / 2;
                int cy = size / 2;
                int maxRadius = 110;
                int n = data.Count;
                if (n < 3) return null;

                using var bmp = new Bitmap(size, size);
                using var g = Graphics.FromImage(bmp);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(White);

                var fillColor = System.Drawing.Color.FromArgb(80, 59, 130, 246);
                var lineColor = System.Drawing.Color.FromArgb(37, 99, 235);
                var pointColor = System.Drawing.Color.FromArgb(29, 78, 216);
                var gridColor = System.Drawing.Color.FromArgb(200, 210, 225);

                for (int level = 1; level <= 4; level++)
                {
                    int r = maxRadius * level / 4;
                    var points = new PointF[n];
                    for (int i = 0; i < n; i++)
                    {
                        double angle = -Math.PI / 2 + 2 * Math.PI * i / n;
                        points[i] = new PointF(cx + (float)(r * Math.Cos(angle)), cy + (float)(r * Math.Sin(angle)));
                    }
                    using var gridPen = new Pen(gridColor, 0.5f) { DashStyle = DashStyle.Dot };
                    g.DrawPolygon(gridPen, points);

                    using var scoreFont = new Font("Microsoft YaHei", 7, FontStyle.Regular);
                    var str = $"{level * 25}";
                    g.DrawString(str, scoreFont, new SolidBrush(TextGray), cx + r + 2, cy - 6);
                }

                for (int i = 0; i < n; i++)
                {
                    double angle = -Math.PI / 2 + 2 * Math.PI * i / n;
                    var endX = cx + (float)(maxRadius * Math.Cos(angle));
                    var endY = cy + (float)(maxRadius * Math.Sin(angle));
                    using var axisPen = new Pen(gridColor, 0.5f);
                    g.DrawLine(axisPen, cx, cy, endX, endY);
                }

                var dataPoints = new PointF[n];
                for (int i = 0; i < n; i++)
                {
                    double angle = -Math.PI / 2 + 2 * Math.PI * i / n;
                    float r = maxRadius * data[i].Score / 100f;
                    dataPoints[i] = new PointF(cx + (float)(r * Math.Cos(angle)), cy + (float)(r * Math.Sin(angle)));
                }

                using var fillBrush = new SolidBrush(fillColor);
                g.FillPolygon(fillBrush, dataPoints);

                using var linePen = new Pen(lineColor, 2f);
                g.DrawPolygon(linePen, dataPoints);

                foreach (var pt in dataPoints)
                {
                    g.FillEllipse(new SolidBrush(pointColor), pt.X - 5, pt.Y - 5, 10, 10);
                    g.FillEllipse(new SolidBrush(White), pt.X - 3, pt.Y - 3, 6, 6);
                }

                for (int i = 0; i < n; i++)
                {
                    double angle = -Math.PI / 2 + 2 * Math.PI * i / n;
                    float lx = cx + (float)((maxRadius + 25) * Math.Cos(angle));
                    float ly = cy + (float)((maxRadius + 25) * Math.Sin(angle));
                    using var labelFont = new Font("Microsoft YaHei", 9, FontStyle.Regular);
                    var labelSize = g.MeasureString(data[i].Standard, labelFont);
                    g.DrawString(data[i].Standard, labelFont, new SolidBrush(TextDark),
                        lx - labelSize.Width / 2, ly - labelSize.Height / 2);
                }

                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                    return ms.ToArray();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[ChartGen] 雷达图生成失败: {ex.Message}");
                return null;
            }
        }
    }
}