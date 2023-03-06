#!/usr/bin/python3
import http.server as hserver


class MockServer(hserver.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        resp = {
            '/direct': 'direct=OK',
            '/http': 'http=OK',
            '/socks': 'socks=OK',
            '/shadowsocks': 'shadowsocks=OK',
            '/trojan': 'trojan=OK',
            '/wireguard': 'wireguard=OK',
        }

        if self.path in resp:
            self.success_resp(resp[self.path])
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes('404 Not Found', 'utf-8'))

    def success_resp(self, content: str):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(content, 'utf-8'))


if __name__ == "__main__":
    web_server = hserver.HTTPServer(('127.0.0.1', 10400), MockServer)
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass
    web_server.server_close()
