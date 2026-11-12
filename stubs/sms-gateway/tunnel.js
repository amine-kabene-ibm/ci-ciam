'use strict';
// Opens a free public https tunnel to a local port with plain ssh (localhost.run, no account, no install) so IBM Verify can reach the SMS gateway stub.
// The URL changes on every start and the tunnel can be refused (offline, firewall): resolve null in that case, never throw.
const { spawn } = require('child_process');

function openTunnel(port, { timeoutMs = 40000 } = {}) {
  return new Promise((resolve) => {
    const ssh = spawn('ssh', ['-T', '-o', 'StrictHostKeyChecking=no', '-o', 'ServerAliveInterval=20', '-o', 'ExitOnForwardFailure=yes', '-R', `80:localhost:${port}`, 'nokey@localhost.run'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false; let buf = '';
    const finish = (v) => { if (!done) { done = true; clearTimeout(timer); resolve(v); } };
    const timer = setTimeout(() => { ssh.kill(); finish(null); }, timeoutMs);
    const onData = (d) => {
      buf += d.toString();
      const m = buf.match(/https:\/\/[a-z0-9]+\.lhr\.life/);
      if (m) finish({ url: m[0], close: () => ssh.kill() });
    };
    ssh.stdout.on('data', onData); ssh.stderr.on('data', onData);
    ssh.on('exit', () => finish(null)); ssh.on('error', () => finish(null));
  });
}

module.exports = { openTunnel };
