# Tap:DNS #

Tap:DNS is a DNS server using Tor and TLS, with caching, filtering, and more.

Features:
* Takes both TCP and UDP connections
* Outgoing connections use TCP, TLSv1.2, and Tor
* DNS requests and responses are rewritten to a simple form, containing only the domain or IP
* Only IPv4 supported
* Caching, with minimum TTL
* Requests for invalid domains and unrecognized TLDs are blocked
* .tap domains are resolved to localhost
* Filtering:
  * Domains (includes all subdomains)
  * Subdomains (prefixes)
  * TLDs (suffixes)
  * Keywords

The Sqlite3 database, `Database/Hosts.tap` stores both cached results and filters. For filters, Type 30 is block and Type 10 is allow.
