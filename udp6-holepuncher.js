#!/bin/node

const child_process = require('node:child_process');
const readline = require('node:readline/promises');

class UDP6HolePuncher {
    constructor() {
        this.armIp6tablesRestore();
        this.armConntrack();
    }

    armIp6tablesRestore() {
        this.ip6t_r = child_process.spawn('ip6tables-restore', ['--noflush']);

        this.ip6t_r.on('exit', this.armIp6tablesRestore.bind(this));
        this.ip6t_r.stdin.on('error', (err) => console.error(err));
    }

    armConntrack() {
        this.conntrack = {
            new: {},
            destroy: {}
        };
        this.conns = new Map();

        this.armConntrackImpl(
            this.conntrack.new,
            ['-E', '-e', 'NEW', '-p', 'udp', '-f', 'ipv6', '-m', '0x2'],
            this.conntrackNewEventCB.bind(this)
        );
        this.armConntrackImpl(
            this.conntrack.destroy,
            ['-E', '-e', 'DESTROY', '-p', 'udp', '-f', 'ipv6'],
            this.conntrackDestroyEventCB.bind(this)
        );
    }

    armConntrackImpl(ref, conntrackOpts, eventCB) {
        ref.proc = child_process.spawn('conntrack', conntrackOpts);
        ref.readlineInterface = readline.createInterface({
            input: ref.proc.stdout,
            crlfDelay: Infinity
        });

        ref.readlineInterface.on('line', (entry) => {
            eventCB(this.parseConntrackEntry(entry));
        });
        ref.proc.on('exit', this.armConntrackImpl.bind(this, ref, conntrackOpts, eventCB));
    }

    conntrackNewEventCB(event) {
        const ip6tEntry = this.buildIP6TEntry(event);
        const connKey = this.genConnKeyFromEvent(event);
        const connCtr = this.conns.get(connKey) || 0;

        if (connCtr === 0) {
            this.ip6t_r.stdin.write(ip6tEntry);
        }

        this.conns.set(connKey, connCtr + 1);
    }

    conntrackDestroyEventCB(event) {
        const connKey = this.genConnKeyFromEvent(event);
        const connCtr = this.conns.get(connKey);

        if (connCtr > 0) {
            const ip6tEntry = this.buildIP6TEntry(event);

            this.ip6t_r.stdin.write(ip6tEntry);

            if (connCtr > 1) {
                this.conns.set(connKey, connCtr - 1);
            } else {
                this.conns.delete(connKey);
            }
        }
    }

    parseConntrackEntry(entry) {
        const ret = {
            event: '',
            addr: '',
            port: ''
        };

        entry.trim().split(/\s+/).forEach((col) => {
            const splitByEq = col.split('=');

            switch (true) {
                case splitByEq.length === 1 && !ret.event:
                    ret.event = col.replace(/^\[|\]$/g, '');
                    break;

                case splitByEq[0] == 'dst':
                    ret.addr = splitByEq[1];
                    break;

                case splitByEq[0] == 'dport':
                    ret.port = splitByEq[1];
                    break;
            }
        });

        return ret;
    }

    genConnKeyFromEvent(event) {
        return JSON.stringify({ addr: event.addr, port: event.port });
    }

    buildIP6TEntry(event) {
        const rule = this.buildIP6TFilterRule(event);

        return [
            '*filter',
            rule,
            'COMMIT',
            ''
        ].join('\n');
    }

    buildIP6TFilterRule(event) {
        return `${this.chooseIP6TCommand(event)} UDP_HOLE_PUNCHING -d ${event.addr}/128 -p udp -m udp --dport ${event.port} -j ACCEPT`;
    }

    chooseIP6TCommand(event) {
        return event.event === 'DESTROY' ? '-D' : '-I';
    }
}

new UDP6HolePuncher();
