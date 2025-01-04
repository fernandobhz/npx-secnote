#!/usr/bin/env node
import { existsSync} from "fs";
import { readFile } from "fs/promises";
import { noteEncrypt } from "./lib/note-encrypt.mjs";
import { noteDecrypt } from "./lib/note-decrypt.mjs";
import { encryptedNoteExtension } from "./consts.mjs";

process.on('uncaughtException', console.error);
process.on('unhandledRejection', console.error);

const [inputFile, password, userKeySalt, userCipherIv] = process.argv.slice(2);
const { log } = console;

const { version } = JSON.parse(await readFile(new URL('./package.json', import.meta.url)));
log(`SecNote version: ${version}\n`);

if (!inputFile || !password) {
  console.error("Usage:\n\tnpx secNote inputFile password");
  process.exit(1);
}

if (!existsSync(inputFile)) {
  console.error(`Error: Input Note "${inputFile}" does not exist`);
  process.exit(1);
}

if (typeof password !== "string") {
  console.error("Error: Password must be a string");
  process.exit(1);
}

if (inputFile.endsWith(encryptedNoteExtension)) {
  await noteDecrypt({ inputFile, password, userKeySalt, userCipherIv });
  log(`Decrypted`);
  process.exit(0);
}

await noteEncrypt({ inputFile, password, userKeySalt, userCipherIv });
log(`Encrypted`);
process.exit(0);
