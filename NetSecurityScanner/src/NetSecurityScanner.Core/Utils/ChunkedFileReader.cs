using System;
using System.Buffers;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Utils
{
  public class ChunkedFileReader : IDisposable
  {
    private readonly int _chunkSize;
    private readonly ArrayPool<byte> _bufferPool;
    private bool _disposed;

    public ChunkedFileReader(int chunkSize = 65536)
    {
      _chunkSize = chunkSize;
      _bufferPool = ArrayPool<byte>.Shared;
    }

    public async Task ReadChunksAsync(string filePath, Func<byte[], int, int, CancellationToken, Task> chunkAction, CancellationToken cancellationToken = default)
    {
      var buffer = _bufferPool.Rent(_chunkSize);
      try
      {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, _chunkSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        int bytesRead;
        long totalRead = 0;

        while ((bytesRead = await stream.ReadAsync(buffer, 0, _chunkSize, cancellationToken).ConfigureAwait(false)) > 0)
        {
          await chunkAction(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
          totalRead += bytesRead;

          if (totalRead % (50 * 1024 * 1024) == 0)
          {
            GC.Collect(0, GCCollectionMode.Optimized, false);
          }
        }
      }
      finally
      {
        _bufferPool.Return(buffer);
      }
    }

    public async Task<string> ReadTextChunksAsync(string filePath, int maxLength = -1, CancellationToken cancellationToken = default)
    {
      var sb = new StringBuilder();
      var buffer = _bufferPool.Rent(_chunkSize);
      try
      {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, _chunkSize, FileOptions.Asynchronous | FileOptions.SequentialScan);
        int bytesRead;
        long totalRead = 0;

        while ((bytesRead = await stream.ReadAsync(buffer, 0, _chunkSize, cancellationToken).ConfigureAwait(false)) > 0)
        {
          sb.Append(Encoding.UTF8.GetString(buffer, 0, bytesRead));
          totalRead += bytesRead;

          if (maxLength > 0 && totalRead >= maxLength)
            break;

          if (totalRead % (50 * 1024 * 1024) == 0)
          {
            GC.Collect(0, GCCollectionMode.Optimized, false);
          }
        }
      }
      finally
      {
        _bufferPool.Return(buffer);
      }

      return sb.ToString();
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