Tap:DNS (The Attenuating Proxy: Deadbolt Name Service) is a DNS server to go with Tap, sharing its design philosophy.

Use with nslookup:
nslookup -port=60053 -vc example.com 127.0.0.1

Use with dig:
dig -p 60053 +tcp example.com @127.0.0.1 
