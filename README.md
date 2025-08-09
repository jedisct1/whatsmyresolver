# whatsmyresolver

This is the source code of the `resolver.00f.net` service.

It responds to DNS queries with the client (resolver) IP address.

Public demo API
---------------

```bash
$ dig +short resolver.dnscrypt.info
74.125.181.207
```
-> Aww crap, this VPN service is actually sending DNS queries to Google.

For more information:

```bash
$ dig +txt resolver.dnscrypt.info
resolver.dnscrypt.info. 10      IN      TXT     "Resolver IP: 90.84.9.116"
resolver.dnscrypt.info. 10      IN      TXT     "CD flag set (Checking Disabled)"
resolver.dnscrypt.info. 10      IN      TXT     "EDNS0 client subnet: 2.13.157.0/24/0"
resolver.dnscrypt.info. 10      IN      TXT     "EDNS0 UDP buffer size: 1400"
resolver.dnscrypt.info. 10      IN      TXT     "DNSSEC OK (DO bit set)"
```

Installation
------------

```bash
$ go install github.com/jedisct1/whatsmyresolver/cmd/whatsmyresolver@latest
```

Or build from source:
```bash
$ git clone https://github.com/jedisct1/whatsmyresolver
$ cd whatsmyresolver
$ go build -o whatsmyresolver ./cmd/whatsmyresolver
$ ./whatsmyresolver -listen <myresolver ip address>:53
```

And delegate a zone to this IP:
```
resolver.example.com. IN NS resolver-ns.example.com.
resolver-ns.example.com IN A <myresolver ip address>
```
