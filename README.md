syslog-dup

A python program for capturing syslog events off the wire and sending them as normal syslog events to another syslog collector.

```
usage: syslog_dup.py [-h] [-d] [-q] [-n] [-c COUNT] [-s [IP]] [-o PORT] -i IF
                     dst dport ...

syslog duplicator - sniffs syslog packets and resends them to a new logger

positional arguments:
  dst                   destination host
  dport                 destination port
  ...                   bpf expression (default: udp and port 514)

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debug messages
  -q, --quiet           suppress output messages
  -n, --no-output       suppress output packets
  -c COUNT, --count COUNT
                        number of packets to capture before exit
  -s [IP], --src [IP]   source address (unspecified: use 10.207.9.35; default:
                        IP in sniffed packet)
  -o PORT, --sport PORT
                        source port to use in output (default: port in sniffed
                        packet
  -i IF, --iface IF     interface to sniff
```
