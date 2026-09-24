"""启动一个测试 HTTP 服务,模拟真实开放端口,用于验证扫描器能发现端口"""
import http.server
import socketserver
import threading
import sys
import time

PORTS = [18080, 19222, 19999]
started = []

class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'TestServer OK')
    def log_message(self, *args, **kwargs):
        pass  # 静默

def start_on_port(port):
    try:
        httpd = socketserver.TCPServer(('127.0.0.1', port), QuietHandler)
        httpd.allow_reuse_address = True
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        started.append(httpd)
        print(f"  ✓ 127.0.0.1:{port} LISTENING", flush=True)
        return True
    except OSError as e:
        print(f"  ✗ 127.0.0.1:{port} 启动失败: {e}", flush=True)
        return False

if __name__ == '__main__':
    print("测试 HTTP 服务启动中...", flush=True)
    for p in PORTS:
        start_on_port(p)
    print(f"\n{len(started)}/{len(PORTS)} 端口已就绪", flush=True)
    print("服务运行中,按 Ctrl+C 停止...", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
        for httpd in started:
            httpd.shutdown()
