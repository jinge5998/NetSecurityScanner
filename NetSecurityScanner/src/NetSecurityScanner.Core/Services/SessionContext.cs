using System;
using NetSecurityScanner.Models;

namespace NetSecurityScanner.Services
{
    /// <summary>
    /// 当前登录用户会话上下文（单例）。
    /// 提供 Current 属性与 Changed 事件，UI 可订阅事件刷新按钮可用性。
    /// </summary>
    public sealed class SessionContext
    {
        private static readonly Lazy<SessionContext> _instance = new(() => new SessionContext());
        public static SessionContext Instance => _instance.Value;

        private SessionContext() { }

        private User? _current;
        public User? Current
        {
            get => _current;
            set
            {
                if (_current?.Id == value?.Id && _current?.Username == value?.Username)
                    return;
                _current = value;
                Changed?.Invoke(this, EventArgs.Empty);
            }
        }

        public bool IsLoggedIn => _current != null;

        public event EventHandler? Changed;

        public void Clear()
        {
            Current = null;
        }
    }
}
