import fs from "fs/promises";
import { existsSync } from "fs";
import { encryptedNoteExtension } from "../consts.mjs";
import { scryptSync, randomBytes, createCipheriv } from "crypto";
import { Buffer } from "buffer";

export const noteEncrypt = async ({ inputFile, password, userKeySalt = null, userCipherIv = null }) => {
  const outputFileName = `${inputFile}.${encryptedNoteExtension}`;

  if (!existsSync(inputFile)) {
    console.error(`Error: The inputfile file ${inputFile} doesn't exists`);
    process.exit(1);
  }

  if (existsSync(outputFileName)) {
    console.error(`Error: The output file ${outputFileName} already exists`);
    process.exit(1);
  }

  const text = await fs.readFile(inputFile, "utf8");

  let keySalt;

  if (userKeySalt) {
    keySalt = userKeySalt;
  } else {
    keySalt = randomBytes(16);
  }

  let cipherIv;

  if (userCipherIv) {
    cipherIv = userCipherIv;
  } else {
    cipherIv = randomBytes(16);
  }

  const algorithm = "aes-256-cbc";
  const key = scryptSync(password, keySalt, 32);
  const cipher = createCipheriv(algorithm, key, cipherIv);
  const encrypted = cipher.update(text, `utf8`, `hex`) + cipher.final(`hex`);
  const hexKeySalt = keySalt.toString(`hex`);
  const hexCipherIv = cipherIv.toString(`hex`);
  const enctypedData = Buffer.from(JSON.stringify({ encrypted, hexKeySalt, hexCipherIv }), `utf8`).toString(`base64`);

  await fs.writeFile(outputFileName, enctypedData);
  console.warn(`WARNING: The npx secnote ENCRYPTION is incompatible with secnote-frg.herokuapp.com, although the DECRYPTION is compatible\n\n`);
};
