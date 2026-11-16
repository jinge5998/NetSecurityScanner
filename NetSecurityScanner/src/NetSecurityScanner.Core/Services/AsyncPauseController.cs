using System.Threading;
using System.Threading.Tasks;

namespace NetSecurityScanner.Core.Services
{
    /// <summary>
    /// 异步暂停闸门：Pause 后 WaitIfPausedAsync 阻塞，Resume 放行；等待支持取消。
    /// 每次批量扫描运行创建一个实例，运行结束后丢弃。
    /// </summary>
    public class AsyncPauseController
    {
        private readonly object _gate = new();
        private TaskCompletionSource<bool> _tcs = NewTcs();

        public bool IsPaused { get; private set; }

        private static TaskCompletionSource<bool> NewTcs() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Pause()
        {
            lock (_gate) { IsPaused = true; }
        }

        public void Resume()
        {
            lock (_gate)
            {
                IsPaused = false;
                _tcs.TrySetResult(true);
                _tcs = NewTcs();
            }
        }

        public async Task WaitIfPausedAsync(CancellationToken ct)
        {
            Task wait;
            lock (_gate)
            {
                if (!IsPaused) return;
                wait = _tcs.Task;
            }
            // WaitAsync(ct)：按等待者取消，不污染共享 TCS（.NET 6+）
            await wait.WaitAsync(ct).ConfigureAwait(false);
        }
    }
}
