import * as fs from "node:fs/promises";
import * as os from "node:os";
import path from "node:path";
import * as actionsCore from "@actions/core";
import { Tail } from "tail";

export function getTrinaryInput(
  name: string,
): "enabled" | "disabled" | "no-preference" {
  const trueValue = ["true", "True", "TRUE", "enabled"];
  const falseValue = ["false", "False", "FALSE", "disabled"];
  const noPreferenceValue = ["", "null", "no-preference"];

  const val = actionsCore.getInput(name);
  if (trueValue.includes(val)) {
    return "enabled";
  }
  if (falseValue.includes(val)) {
    return "disabled";
  }
  if (noPreferenceValue.includes(val)) {
    return "no-preference";
  }

  const possibleValues = trueValue
    .concat(falseValue)
    .concat(noPreferenceValue)
    .join(" | ");
  throw new TypeError(
    `Input ${name} does not look like a trinary, which requires one of:\n${possibleValues}`,
  );
}

export function tailLog(daemonDir: string): Tail {
  const log = new Tail(path.join(daemonDir, "daemon.log"));
  actionsCore.debug(`tailing daemon.log...`);
  log.on("line", (line) => {
    actionsCore.info(line);
  });
  return log;
}

export async function netrcPath(): Promise<string> {
  const expectedNetrcPath = path.join(
    process.env["RUNNER_TEMP"] ?? os.tmpdir(),
    "determinate-nix-installer-netrc",
  );
  try {
    await fs.access(expectedNetrcPath);
    return expectedNetrcPath;
  } catch {
    // `nix-installer` was not used, the user may be registered with FlakeHub though.
    const destinedNetrcPath = path.join(
      process.env["RUNNER_TEMP"] ?? os.tmpdir(),
      "magic-nix-cache-netrc",
    );
    try {
      await flakeHubLogin(destinedNetrcPath);
    } catch (e) {
      actionsCore.info(
        "FlakeHub Cache is disabled due to missing or invalid token",
      );
      actionsCore.info(
        `If you're signed up for FlakeHub Cache, make sure that your Actions config has a \`permissions\` block with \`id-token\` set to "write" and \`contents\` set to "read"`,
      );
      actionsCore.debug(`Error while logging into FlakeHub: ${e}`);
    }
    return destinedNetrcPath;
  }
}

async function flakeHubLogin(netrc: string): Promise<void> {
  const jwt = await actionsCore.getIDToken("api.flakehub.com");

  await fs.writeFile(
    netrc,
    [
      `machine api.flakehub.com login flakehub password ${jwt}`,
      `machine flakehub.com login flakehub password ${jwt}`,
      `machine cache.flakehub.com login flakehub password ${jwt}`,
    ].join("\n"),
  );

  actionsCore.info("Logged in to FlakeHub.");
}
