# Guide to using this ips
## Setup
### 1) Clone the repo
git clone https://github.com/eysless/Gormiku.git
cd Gormiku

### 2) Create and enable the venv
python3 -m venv .venv
source .venv/bin/activate

### 3) Install mitmproxy
pip install mitmproxy

### 4) Enable ip forwarding
- `sysctl -w net.ipv4.ip_forward=1`
- `sysctl -w net.ipv6.conf.all.forwarding=1`

### 5) Disable redirects 
- `sysctl -w net.ipv4.conf.all.send_redirects=0`

If you want to persist this across reboots, you need to adjust your /etc/sysctl.conf

### 6) Add the iptables ruleset: 
```sh
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
iptables -t nat -A OUTPUT  -o lo -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
ip6tables -t nat -A OUTPUT -o lo -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
```
If you want to persist this across reboots, you can use the iptables-persistent

### 7) Fire up the proxy
```
mitmproxy --mode transparent --showhost --set block_global=false -s main.py --listen-port {mitmproxy port}
```

## HOW TO ADD CUSTOM RULES
1. Create your own file in the rules folder (read [template](https://github.com/eysless/Gormiku/blob/main/rules/template.py) for how to do it)
2. Create your rule:
    - Custiom function go in the _FUNCTIONS list
    - Custom regexes go in the _PATTERNS list
3. Profit???


# IN CASE OF PROBLEMS
to remove all rules do:
```sh
iptables -t nat -D PREROUTING -i eth0 -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
ip6tables -t nat -D PREROUTING -i eth0 -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
iptables -t nat -D OUTPUT  -o lo -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
ip6tables -t nat -D OUTPUT -o lo -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
```
for every service
