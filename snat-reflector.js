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
    }

    armConntrack() {
        const proc = child_process.spawn('conntrack', ['-E', '-e', 'NEW,DESTROY', '-p', 'udp', '-f', 'ipv4', '-n']);
        const readlineInterface = readline.createInterface({
            input: proc.stdout,
            crlfDelay: Infinity,
        });

        readlineInterface.on('line', (entry) => {
            const parsed = this.parseConntrackEntry(entry);
            const iptNatEntry = `${parsed.event === 'DESTROY' ? '-D' : '-I'} PREROUTING -d ${parsed.mapped.addr}/32 -p udp -m udp --dport ${parsed.mapped.port} -j DNAT --to-destination ${parsed.origin.addr}:${parsed.origin.port}`;
            const iptForwardEntry = `${parsed.event === 'DESTROY' ? '-D' : '-I'} FORWARD -d ${parsed.origin.addr}/32 -p udp -m udp --dport ${parsed.origin.port} -j ACCEPT`;

            // console.log(parsed);
            this.ipt_r.stdin.write(
                [
                    '*nat',
                    iptNatEntry,
                    'COMMIT',

                    '*filter',
                    iptForwardEntry,
                    'COMMIT',
                ].join('\n') + '\n\n'
            );
        });

        this.conntrack = {
            proc,
            readlineInterface
        };
        proc.on('exit', this.armConntrack.bind(this));
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
}

new SNATReflector();
