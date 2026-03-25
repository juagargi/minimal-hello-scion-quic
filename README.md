# Minimal QUIC over SCION example

To run it, you need to have access to two SCION daemons and border routers.
The easiest is to just run a local topology, e.g. in scionproto's directory run:
```
./scion.sh stop || true
rm -rf gen
./scion.sh topology -c topology/tiny.topo
./scion.sh start
```

Then collect the addresses of two daemons, e.g. for 111 and 110:
```
SCIOND_SERVER=$(./scion.sh sciond-addr 110)
SCIOND_CLIENT=$(./scion.sh sciond-addr 111)
```

Coming back to this repository directory, run the server:
```
SCION_DAEMON_ADDRESS="$SCIOND_SERVER" go run ./ -mode server
```

Then run the client:
```
SCION_DAEMON_ADDRESS="$SCIOND_CLIENT" go run ./ -mode client -remote 1-ff00:0:110,127.0.0.1:40000
```

The client should finish with exit code 0.
