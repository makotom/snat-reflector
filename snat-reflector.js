#!/bin/node

const child_process = require('node:child_process');
const readline = require('node:readline/promises');

class SNATReflector {
    constructor() {
        this.armIptablesRestore();
        this.armConntrack();
    }

    armIptablesRestore() {
        this.ipt_r = child_process.spawn('iptables-restore', ['--noflush']);

        this.ipt_r.on('exit', this.armIptablesRestore.bind(this));
        this.ipt_r.stdin.on('error', (err) => console.error(err));
    }

    armConntrack() {
        this.conntrack = {};
        this.conntrack.proc = child_process.spawn('conntrack', ['-E', '-e', 'NEW,DESTROY', '-p', 'udp', '-f', 'ipv4', '-n']);
        this.conntrack.readlineInterface = readline.createInterface({
            input: this.conntrack.proc.stdout,
            crlfDelay: Infinity
        });

        this.conntrack.readlineInterface.on('line', (entry) => {
            const parsed = this.parseConntrackEntry(entry);
            const iptEntry = this.buildIPTEntry(parsed);

            this.ipt_r.stdin.write(iptEntry);
        });
        this.conntrack.proc.on('exit', this.armConntrack.bind(this));
    }

    parseConntrackEntry(entry) {
        const ret = {
            event: '',
            origin: {},
            mapped: {}
        };

        entry.trim().split(/\s+/).forEach((col) => {
            const splitByEq = col.split('=');

            switch (true) {
                case splitByEq.length === 1 && !ret.event:
                    ret.event = col.replace(/^\[|\]$/g, '');
                    break;

                case splitByEq[0] == 'src' && !ret.origin.addr:
                    ret.origin.addr = splitByEq[1];
                    break;

                case splitByEq[0] == 'sport' && !ret.origin.port:
                    ret.origin.port = splitByEq[1];
                    break;

                case splitByEq[0] == 'dst' && !!ret.origin.port:
                    ret.mapped.addr = splitByEq[1];
                    break;

                case splitByEq[0] == 'dport' && !!ret.mapped.addr:
                    ret.mapped.port = splitByEq[1];
                    break;
            }
        });

        return ret;
    }

    buildIPTEntry(event) {
        const iptDNATRule = this.buildIPTDNATRule(event);
        const iptForwardRule = this.buildIPTForwardRule(event);

        return [
            '*nat',
            iptDNATRule,
            'COMMIT',
            '',
            '*filter',
            iptForwardRule,
            'COMMIT',
            ''
        ].join('\n');
    }

    buildIPTDNATRule(event) {
        return `${this.chooseIPTCommand(event)} PREROUTING -d ${event.mapped.addr}/32 -p udp -m udp --dport ${event.mapped.port} -j DNAT --to-destination ${event.origin.addr}:${event.origin.port}`;
    }

    buildIPTForwardRule(event) {
        return `${this.chooseIPTCommand(event)} FORWARD -d ${event.origin.addr}/32 -p udp -m udp --dport ${event.origin.port} -j ACCEPT`;
    }

    chooseIPTCommand(event) {
        return event.event === 'DESTROY' ? '-D' : '-I';
    }
}

new SNATReflector();
