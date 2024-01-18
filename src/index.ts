// Main

import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn, exec } from 'node:child_process';
import { openSync } from 'node:fs';
import { setTimeout } from 'timers/promises';
import { inspect, promisify } from 'node:util';

import * as core from '@actions/core';
import { Tail } from 'tail';
import got from "got";

const ENV_CACHE_DAEMONDIR = 'MAGIC_NIX_CACHE_DAEMONDIR';

const gotClient = got.extend({
  retry: {
    limit: 5,
    methods: [ 'POST', 'GET', 'PUT', 'HEAD', 'DELETE', 'OPTIONS', 'TRACE' ],
  },
  hooks: {
    beforeRetry: [
      (error, retryCount) => {
        core.info(`Retrying after error ${error.code}, retry #: ${retryCount}`);
      }
    ],
  },
});


function getCacherUrl() : string {
  const runnerArch = process.env.RUNNER_ARCH;
  const runnerOs = process.env.RUNNER_OS;
  const binarySuffix = `magic-nix-cache-${runnerArch}-${runnerOs}`;
  const urlPrefix = `https://install.determinate.systems/magic-nix-cache-priv`;
  if (core.getInput('source-url')) {
    return core.getInput('source-url');
  }

  if (core.getInput('source-tag')) {
    return `${urlPrefix}/tag/${core.getInput('source-tag')}/${binarySuffix}`;
  }

  if (core.getInput('source-pr')) {
    return `${urlPrefix}/pr/${core.getInput('source-pr')}/${binarySuffix}`;
  }

  if (core.getInput('source-branch')) {
    return `${urlPrefix}/branch/${core.getInput('source-branch')}/${binarySuffix}`;
  }

  if (core.getInput('source-revision')) {
    return `${urlPrefix}/rev/${core.getInput('source-revision')}/${binarySuffix}`;
  }

  return `${urlPrefix}/latest/${binarySuffix}`;
}

async function fetchAutoCacher() {
  const binary_url = getCacherUrl();
  core.info(`Fetching the Magic Nix Cache from ${binary_url}`);

  const { stdout } = await promisify(exec)(`curl "${binary_url}" | xz -d | nix-store --import`);

  const paths = stdout.split(os.EOL);

  // Since the export is in reverse topologically sorted order, magic-nix-cache is always the penultimate entry in the list (the empty string left by split being the last).
  const last_path = paths.at(-2);

  return `${last_path}/bin/magic-nix-cache`;
}

function tailLog(daemonDir) {
  const log = new Tail(path.join(daemonDir, 'daemon.log'));
  core.debug(`tailing daemon.log...`);
  log.on('line', (line) => {
    core.info(line);
  });
  return log;
}

async function setUpAutoCache() {
  const tmpdir = process.env['RUNNER_TEMP'] || os.tmpdir();
  const required_env = ['ACTIONS_CACHE_URL', 'ACTIONS_RUNTIME_URL', 'ACTIONS_RUNTIME_TOKEN'];

  var anyMissing = false;
  for (const n of required_env) {
    if (!process.env.hasOwnProperty(n)) {
      anyMissing = true;
      core.warning(`Disabling automatic caching since required environment ${n} isn't available`);
    }
  }

  if (anyMissing) {
    return;
  }

  core.debug(`GitHub Action Cache URL: ${process.env['ACTIONS_CACHE_URL']}`);

  const daemonDir = await fs.mkdtemp(path.join(tmpdir, 'magic-nix-cache-'));

  var daemonBin: string;
  if (core.getInput('source-binary')) {
    daemonBin = core.getInput('source-binary');
  } else {
    daemonBin = await fetchAutoCacher();
  }

  var runEnv;
  if (core.isDebug()) {
    runEnv = {
      RUST_LOG: "trace,magic_nix_cache=debug,gha_cache=debug",
      RUST_BACKTRACE: "full",
      ...process.env
    };
  } else {
    runEnv = process.env;
  }

  // Start the server. Once it is ready, it will notify us via file descriptor 3.
  const outputPath = `${daemonDir}/daemon.log`;
  const output = openSync(outputPath, 'a');
  const log = tailLog(daemonDir);
  const notifyFd = 3;
  const daemon = spawn(
    daemonBin,
    [
      '--notify-fd', String(notifyFd),
      '--listen', core.getInput('listen'),
      '--upstream', core.getInput('upstream-cache'),
      '--diagnostic-endpoint', core.getInput('diagnostic-endpoint'),
      '--nix-conf', `${process.env["HOME"]}/.config/nix/nix.conf`
    ].concat(
      core.getInput('use-flakehub') === 'true' ? [
        '--use-flakehub',
        '--flakehub-cache-server', core.getInput('flakehub-cache-server'),
        '--flakehub-api-server', core.getInput('flakehub-api-server'),
        '--flakehub-api-server-netrc', path.join(process.env['RUNNER_TEMP'], 'determinate-nix-installer-netrc'),
      ] : []).concat(
        core.getInput('use-gha-cache') === 'true' ? [
          '--use-gha-cache'
        ] : []),
    {
      stdio: ['ignore', output, output, 'pipe'],
      env: runEnv,
      detached: true
    }
  );

  const pidFile = path.join(daemonDir, 'daemon.pid');
  await fs.writeFile(pidFile, `${daemon.pid}`);

  await new Promise<void>((resolve, reject) => {
    daemon.stdio[notifyFd].on('data', (data) => {
      if (data.toString().trim() == 'INIT') {
        resolve();
      }
    });

    daemon.on('exit', async (code, signal) => {
      if (signal) {
        reject(new Error(`Daemon was killed by signal ${signal}`));
      } else if (code) {
        reject(new Error(`Daemon exited with code ${code}`));
      } else {
        reject(new Error(`Daemon unexpectedly exited`));
      }
    });
  });

  daemon.unref();

  core.info('Launched Magic Nix Cache');
  core.exportVariable(ENV_CACHE_DAEMONDIR, daemonDir);

  log.unwatch();
}

async function notifyAutoCache() {
  const daemonDir = process.env[ENV_CACHE_DAEMONDIR];

  if (!daemonDir) {
    return;
  }

  try {
    core.debug(`Indicating workflow start`);
    const res: any = await gotClient.post(`http://${core.getInput('listen')}/api/workflow-start`).json();
    core.debug(`back from post`);
    core.debug(res);
  } catch (e) {
    core.info(`Error marking the workflow as started:`);
    core.info(inspect(e));
    core.info(`Magic Nix Cache may not be running for this workflow.`);
  }
}

async function tearDownAutoCache() {
  const daemonDir = process.env[ENV_CACHE_DAEMONDIR];

  if (!daemonDir) {
    core.debug('magic-nix-cache not started - Skipping');
    return;
  }

  const pidFile = path.join(daemonDir, 'daemon.pid');
  const pid = parseInt(await fs.readFile(pidFile, { encoding: 'ascii' }));
  core.debug(`found daemon pid: ${pid}`);
  if (!pid) {
    throw new Error("magic-nix-cache did not start successfully");
  }

  const log = tailLog(daemonDir);

  try {
    core.debug(`about to post to localhost`);
    const res: any = await gotClient.post(`http://${core.getInput('listen')}/api/workflow-finish`).json();
    core.debug(`back from post`);
    core.debug(res);
  } finally {
    await setTimeout(5000);

    core.debug(`unwatching the daemon log`);
    log.unwatch();
  }

  core.debug(`killing`);
  try {
    process.kill(pid, 'SIGTERM');
  } catch (e) {
    if (e.code !== 'ESRCH') {
      throw e;
    }
  }
}

const isPost = !!process.env['STATE_isPost'];

try {
  if (!isPost) {
    core.saveState('isPost', 'true');
    await setUpAutoCache();
    await notifyAutoCache();
  } else {
    await tearDownAutoCache();
  }
} catch (e) {
  core.info(`got an exception:`);
  core.info(e);

  if (!isPost) {
    core.setFailed(e.message);
    throw e;
  } else {
    core.info("not considering this a failure: finishing the upload is optional, anyway.");
    process.exit();
  }}

core.debug(`rip`);

