## How to build CoreDNS with the fanout plugin

There are two ways to build a CoreDNS binary with the fanout plugin.

#### Build via CoreDNS source code

```bash
git clone https://github.com/coredns/coredns
cd coredns
echo "fanout:github.com/TomTonic/fanout" >> plugin.cfg
make
```

#### Build via custom `main.go` file

Create your own `main.go` and build a custom CoreDNS binary. See the [official example](https://coredns.io/2017/07/25/compile-time-enabling-or-disabling-plugins/).

A ready-made `main.go` and `Dockerfile` are included in this directory:

```bash
go build -o coredns/coredns coredns/main.go
docker build coredns/. -t "${ORG}/coredns:${TAG}"
```