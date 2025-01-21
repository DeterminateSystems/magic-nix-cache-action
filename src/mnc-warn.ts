import actionsCore from "@actions/core";
import glob from "@actions/glob";
import { stringifyError } from "detsys-ts";
import * as fs from "node:fs/promises";

export async function warnOnMnc(): Promise<void> {
  const cwd = process.cwd();

  const patterns = [
    ".github/actions/*.yaml",
    ".github/actions/*.yml",
    ".github/workflows/*.yaml",
    ".github/workflows/*.yml",
  ];
  const globber = await glob.create(patterns.join("\n"));
  const files = await globber.glob();

  for (const file of files) {
    try {
      const relativeFilePath = file.replace(cwd, ".");
      const lines = (await fs.readFile(file, { encoding: "utf8" })).split("\n");

      for (const lineIdx of lines.keys()) {
        const line = lines[lineIdx];

        if (
          line
            .toLowerCase()
            .includes("determinatesystems/magic-nix-cache-action")
        ) {
          const actionPosition = line
            .toLowerCase()
            .indexOf("determinatesystems/magic-nix-cache-action");
          const actionPositionEnd =
            actionPosition + "determinatesystems/magic-nix-cache-action".length;

          const newLine = line.replace(
            /DeterminateSystems\/magic-nix-cache-action/gi,
            "DeterminateSystems/flakehub-cache-action",
          );
          actionsCore.warning(
            [
              "Magic Nix Cache has been deprecated due to a change in the underlying GitHub APIs and will stop working on 1 February 2025.",
              "To continue caching Nix builds in GitHub Actions, use FlakeHub Cache instead.",
              "",
              "Replace...",
              line,
              "",
              "...with...",
              newLine,
              "",
              "For more details: https://dtr.mn/magic-nix-cache-eol",
            ].join("\n"),
            {
              title: "Magic Nix Cache is deprecated",
              file: relativeFilePath,
              startLine: lineIdx + 1,
              startColumn: actionPosition,
              endColumn: actionPositionEnd,
            },
          );
        }
      }
    } catch (err) {
      actionsCore.debug(stringifyError(err));
    }
  }
}
