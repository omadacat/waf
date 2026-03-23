# Web Application Firewall

As cybersecurity risks continue to rise, web application firewalls have become a fundamental component of website security. `waf` is a self‑contained, lightweight Web Application Firewall written in Go. It sits behind your existing Nginx reverse proxy and provides a layered defense against malicious bots, AI scrapers, and common web attacks (XSS, SQL injection, path traversal). It combines techniques from several open‑source projects: 

- [SafeLine WAF](https://github.com/chaitin/safeline)
- [csswaf](https://github.com/yzqzss/csswaf)
- [ngx_http_js_challenge_module](https://github.com/solidwall/ngx_http_js_challenge_module)
- [haproxy-protection](https://github.com/OpenNSM/haproxy-protection)
- [pow-bot-deterrent](https://github.com/jwhett/pow-bot-deterrent)
- [go-away](https://github.com/StalkR/go-away)
- [anubis](https://github.com/jonaslu/anubis)
- [powxy](https://github.com/landaire/powxy)

## Installation

### 1. Clone the WAF
```
git clone https://git.omada.cafe/atf/waf.git
cd waf
```

### 2. Build the WAF
```
./build.sh
```

The script creates a static binary named `waf` in the current directory.  
To install system‑wide, run with `--install`:

```
sudo ./build.sh --install
```

### 3. Configure the WAF

Create `/etc/waf/config.yaml` using the provided example. At minimum, set:

- `token_secret` a strong secret (use `openssl rand -hex 32`).
- `backends` map of domain to backend URL.

Copy the rules and optional bot list:

```
sudo mkdir -p /etc/waf
sudo cp config.yaml /etc/waf/
sudo cp -r rules /etc/waf/
```

### 4. Set Up the WAF systemd Service

```
sudo cp systemd/waf.service /etc/systemd/system/
sudo cp systemd/environment /etc/waf/environment
sudo chmod 600 /etc/waf/environment
sudo useradd -r -s /sbin/nologin -d /var/empty/waf waf
sudo chown -R waf:waf /etc/waf
sudo systemctl daemon-reload
sudo systemctl enable --now waf
```

Check status: `systemctl status waf`  
View logs: `journalctl -u waf -f`

### 5. Update Nginx Configuration

In each server block that should be protected, change the `proxy_pass` to point to the WAF:

```
location / {
    proxy_pass http://127.0.0.1:7616;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;   # important for streaming challenges
}
```

Add the WebSocket upgrade map to your `nginx.conf` (inside the `http` block):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

Test and reload Nginx:

```
sudo nginx -t && sudo systemctl reload nginx
```

## Testing Locally

1. Start a test backend (e.g., Python HTTP server):
   ```
   cd /tmp
   python3 -m http.server 8080
   ```
2. Create a test `config.yaml` with:
   ```
   listen_addr: "127.0.0.1:7616"
   token_secret: "test-secret"
   backends: { "localhost": "http://127.0.0.1:8080" }
   ```
3. Run the WAF:
   ```
   ./waf -config test-config.yaml
   ```
4. In a browser, visit `http://localhost:7616/`. You should be challenged and then see the directory listing.

## License

- **Source code** – GNU General Public License v2.0 or later (see [LICENSE](LICENSE)).
- **Documentation** – Creative Commons Attribution‑ShareAlike 4.0 International.