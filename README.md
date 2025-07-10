# Guide to using this ips
## Setup
Use setup.sh, or if you need the commands use these:
Enable ip forwarding
- sysctl -w net.ipv4.ip_forward=1
- sysctl -w net.ipv6.conf.all.forwarding=1

Disable redirects 
- sysctl -w net.ipv4.conf.all.send_redirects=0

If you want to persist this across reboots, you need to adjust your /etc/sysctl.conf

Iptables ruleset: 
```sh
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
ip6tables -t nat -A PREROUTING -i eth0 -p tcp --dport {Service port} -j REDIRECT --to-port {mitmproxy port}
```
If you want to persist this across reboots, you can use the iptables-persistent

Then fire up the proxy
mitmproxy --mode transparent --showhost --set block_global=false -s main.py -listen_port {mitmproxy port}

