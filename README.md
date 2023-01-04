# SNAT Reflector

User-space gap filler to implement full-cone NAT on Linux-based brouters - a Node.js script to add/delete DNAT rules based on SNAT entries controlled under connection tracking by kernel.

## Usage

### Prerequisites

Versions are that tested at the time of this writing.

-   Linux (6.1.2)
-   systemd (252)
-   Node.js (19.3.0)
-   conntrack-tools (1.4.7)
-   iptables (1.8.8, nftables-backed - aka iptables-nft)
    -   `UDP_HOLE_PUNCHING` chain available under tables `filter` and `nat`

### Installation

Note: Root needed.

1.  `install -m 0755 -o root -g root snat-reflector.js /usr/local/bin/snat-reflector`
2.  `install -m 0644 -o root -g root snat-reflector.service /etc/systemd/system/snat-reflector.service`
3.  `systemctl enable --now snat-reflector.service`

# UDP6 Hole Puncher

User-space gap filler for UDP-over-IPv6 hole punching - a Node.js script to add/delete IP filter rules based on connection tracking by kernel.

It's a variation of SNAT Reflector, with small differences that it's for IPv6, and it's based on connmark instead of SNAT.

## Usage

### Prerequisites

Versions are that tested at the time of this writing.

-   Linux (6.1.2)
-   systemd (252)
-   Node.js (19.3.0)
-   conntrack-tools (1.4.7)
-   iptables (1.8.8, nftables-backed - aka iptables-nft)
    -   `UDP_HOLE_PUNCHING` chain available under table `filter`
-   Connection mark `0x2/0x2` added (with preconfigured netfilter) to hole-punching egress connections

### Installation

Note: Root needed.

1.  `install -m 0755 -o root -g root udp6-holepuncher.js /usr/local/bin/udp6-holepuncher`
2.  `install -m 0644 -o root -g root udp6-holepuncher.service /etc/systemd/system/udp6-holepuncher.service`
3.  `systemctl enable --now udp6-holepuncher.service`
