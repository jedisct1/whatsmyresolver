# whatmyresolver

This is the source code of the `resolver.00f.net` service.

It responds to DNS queries with the client (resolver) IP address.

Public demo API
---------------

```bash
$ dig +short resolver.dnscrypt.info
74.125.181.207
```
-> Aww crap, this VPN service is actually sending DNS queries to Google.

Installation
------------

```bash
$ go get github.com/jedisct1/whatsmyresolver
# myresolver -listen <myresolver ip address>:53
```

And delegate a zone to this IP:
```
resolver.example.com. IN NS resolver-ns.example.com.
resolver-ns.example.com IN A <myresolver ip address>
```
