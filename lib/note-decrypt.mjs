import fs from "fs/promises";
import { existsSync } from "fs";
import { encryptedNoteExtension } from "../consts.mjs";
import { scryptSync, createDecipheriv } from "crypto";
import { Buffer } from "buffer";

export const noteDecrypt = async ({ inputFile, password, userKeySalt = null, userCipherIv = null }) => {
  const outputFileName = inputFile.slice(0, inputFile.length - encryptedNoteExtension.length - 1);

  if (!existsSync(inputFile)) {
    console.error(`Error: The inputfile file ${inputFile} doesn't exists`);
    process.exit(1);
  }

  if (existsSync(outputFileName)) {
    console.error(`Error: The output file ${outputFileName} already exists`);
    process.exit(1);
  }

  const enctypedData = await fs.readFile(inputFile, "utf8");
  const { encrypted, iv, hexKeySalt, hexCipherIv } = JSON.parse(Buffer.from(enctypedData, `base64`).toString(`utf8`));

  let keySalt;

  if (userKeySalt) {
    keySalt = userKeySalt;
  } else if (iv) {
    keySalt = Buffer.from(iv, `hex`);
  } else {
    keySalt = Buffer.from(hexKeySalt, `hex`);
  }

  let cipherIv;

  if (userCipherIv) {
    cipherIv = userCipherIv;
  } else if (iv) {
    cipherIv = Buffer.from(iv, `hex`);
  } else {
    cipherIv = Buffer.from(hexCipherIv, `hex`);
  }

  try {
    // npx secnote will use keySalt and cipherIv
    const algorithm = "aes-256-cbc";
    const key = scryptSync(password, keySalt, 32);
    const decipher = createDecipheriv(algorithm, key, cipherIv);
    const decrypted = decipher.update(encrypted, `hex`, `utf8`) + decipher.final(`utf8`);
    await fs.writeFile(outputFileName, decrypted);
  } catch (error) {
    // legacy secnote-frg.herokuapp.com uses hardcoded 'salt' as keySalt, and iv as cipherIv
    const algorithm = "aes-256-cbc";
    const key = scryptSync(password, `salt`, 32);
    const decipher = createDecipheriv(algorithm, key, cipherIv);
    const decrypted = decipher.update(encrypted, `hex`, `utf8`) + decipher.final(`utf8`);
    await fs.writeFile(outputFileName, decrypted);
  }
};
