# SNAT Reflector

User-space gap filler to implement full-cone NAT on Linux-based brouters - a Node.js script to add/delete DNAT rules based on SNAT entries controlled under connection tracking by kernel.

## Usage

### Prerequisites

Versions are that tested at the time of this writing.

- Linux (6.1.1)
- systemd (252)
- Node.js (19.3.0)
- conntrack-tools (1.4.7)
- iptables (1.8.8, with legacy interface)

### Installation

Note: Root needed.

1.  `install -m 0755 -o root -g root snat-reflector.js /usr/local/bin/snat-reflector`
2.  `install -m 0644 -o root -g root snat-reflector.service /etc/systemd/system/snat-reflector.service`
3.  `systemctl enable --now snat-reflector.service`
