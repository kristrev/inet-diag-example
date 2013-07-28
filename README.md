inet-diag-example
=================

For a project I was working on lately, I needed to passively monitor a large
number of TCP sockets. One common way to do is to parse the output of /proc/tcp,
but my goal was to create a "clean" solution and avoid for example text-parsing.

After doing some digging, I discovered the convenient ss-utility (of the
iproute-suite), which does something similar to what I want. ss makes use of
NETLINK and the INET\_DIAG-sockets for a nice way of extracting connection
information. ss has support for all protocols (sockets) supporting exporting
information, so the code is very generic and quite large.

Combined with a lack of INET\_DIAG-documentation (the kernel source is your
friend), I decided to create a small, easy to follow example of how INET\_DIAG
can be used to passively monitor sockets. A detailed description of the example
is available
[here](http://kristrev.github.io/2013/07/26/passive-monitoring-of-sockets-on-linux/).
