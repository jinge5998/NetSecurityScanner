using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using NetSecurityScanner.Core.Services;
using Xunit;

namespace NetSecurityScanner.Tests
{
    public class AsyncPauseControllerTests
    {
        [Fact]
        public async Task WaitIfPausedAsync_NotPaused_CompletesImmediately()
        {
            var controller = new AsyncPauseController();
            await controller.WaitIfPausedAsync(CancellationToken.None);
        }

        [Fact]
        public async Task WaitIfPausedAsync_Paused_BlocksUntilResume()
        {
            var controller = new AsyncPauseController();
            controller.Pause();

            var waitTask = controller.WaitIfPausedAsync(CancellationToken.None);
            await Task.Delay(100);
            waitTask.IsCompleted.Should().BeFalse();

            controller.Resume();
            await waitTask;
        }

        [Fact]
        public async Task WaitIfPausedAsync_Paused_CancellationThrows()
        {
            var controller = new AsyncPauseController();
            controller.Pause();
            using var cts = new CancellationTokenSource(100);

            Func<Task> act = () => controller.WaitIfPausedAsync(cts.Token);
            await act.Should().ThrowAsync<OperationCanceledException>();
        }

        [Fact]
        public async Task Resume_WhenNotPaused_IsIdempotent()
        {
            var controller = new AsyncPauseController();
            controller.Resume();
            await controller.WaitIfPausedAsync(CancellationToken.None);
        }
    }
}
