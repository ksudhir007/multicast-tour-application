multicast-tour-application
==========================
An application which uses raw IP sockets to walk through (tour) an ordered list of nodes in a simulated VMware environment. Raw sockets allow new IPv4 protocols to be implemented in user-space by sending/receiving raw datagrams without link level headers. Implemented ping, ARP and multicast mechanisms in user-space. During the tour each node pings the source node and the group of nodes that are visited on the tour will exchange multicast messages.
