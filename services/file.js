import fs from "fs";
import csv from "csv-parser";
import { log } from "./logger.js";

export const makeDir = (path) => {
  fs.mkdir(path, { recursive: true }, (err) => {
    const logMessage = err
      ? `ERROR, while creating directory at ${path} - error trace: ${err}`
      : `SUCCESS, while creating directory at ${path}`;

    log(logMessage);
  });
};

export const deleteFile = (filePath) => {
  fs.unlink(filePath, (err) => {
    if (err) {
      log(`ERROR, while deleting file at ${filePath} - error trace: ${err}`);
    }
  });
};

export const writeFileAsync = (filePath, fileContentString) => {
  fs.writeFile(filePath, fileContentString, (err) => {
    const logMessage = err
      ? `ERROR, while writing file at ${filePath} - error trace: ${err}`
      : `SUCCESS, while writing file at ${filePath}`;

    log(logMessage);
  });
};

export const appendFileAsync = (filePath, fileContentString) => {
  fs.appendFile(filePath, fileContentString, (err) => {
    if (err) {
      console.log(
        `ERROR, while appending message '${fileContentString}' to a file at ${filePath} - error trace: ${err}`
      );
    }
  });
};

export const csvToArray = (filePath) => {
  return new Promise((resolve, reject) => {
    const result = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on("data", (row) => {
        result.push(row);
      })
      .on("end", () => {
        resolve(result);
      })
      .on("error", (err) => {
        log(
          `ERROR, while parsing csv file at ${filePath} - error trace: ${err}`
        );
        reject(err);
      });
  });
};
