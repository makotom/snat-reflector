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
        this.ipt_r.stdout.on('data', (data) => console.log(data.toString()));
        this.ipt_r.stderr.on('data', (data) => console.error(data.toString()));
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
        const natRule = this.buildIPTNATRule(event);
        const filterRule = this.buildIPTFilterRule(event);

        return [
            '*nat',
            natRule,
            'COMMIT',
            '',
            '*filter',
            filterRule,
            'COMMIT',
            ''
        ].join('\n');
    }

    buildIPTNATRule(event) {
        return `${this.chooseIPTCommand(event)} UDP_HOLE_PUNCHING -d ${event.mapped.addr}/32 -p udp -m udp --dport ${event.mapped.port} -j DNAT --to-destination ${event.origin.addr}:${event.origin.port}`;
    }

    buildIPTFilterRule(event) {
        return `${this.chooseIPTCommand(event)} UDP_HOLE_PUNCHING -d ${event.origin.addr}/32 -p udp -m udp --dport ${event.origin.port} -j ACCEPT`;
    }

    chooseIPTCommand(event) {
        return event.event === 'DESTROY' ? '-D' : '-I';
    }
}

new SNATReflector();
