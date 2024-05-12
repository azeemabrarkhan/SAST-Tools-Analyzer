import fs from "fs";
import path from "path";
import csv from "csv-parser";
import { log } from "./logger.js";
import { nanoid } from "nanoid";

const JSON_OBJECT_LIMIT_PER_FILE = 300;

export const makeDir = (dirPath) => {
  let error;

  fs.mkdir(dirPath, { recursive: true }, (err) => {
    error = err;

    const logMessage = err
      ? `ERROR, while creating directory at ${dirPath} - error trace: ${err}`
      : `SUCCESS, while creating directory at ${dirPath}`;
    if (err) log(logMessage);
  });

  return error ? undefined : dirPath;
};

export const deleteFile = (filePath) => {
  fs.unlink(filePath, (err) => {
    if (err)
      log(`ERROR, while deleting file at ${filePath} - error trace: ${err}`);
  });
};

export const writeFileAsync = (filePath, fileContentString) => {
  fs.writeFile(filePath, fileContentString, (err) => {
    const logMessage = err
      ? `ERROR, while writing file at ${filePath} - error trace: ${err}`
      : `SUCCESS, while writing file at ${filePath}`;

    if (err) log(logMessage);
  });
};

export const writeFile = (filePath, fileContentString) => {
  try {
    fs.writeFileSync(filePath, fileContentString);
  } catch (err) {
    log(`ERROR, while writing file at ${filePath} - error trace: ${err}`);
  }
};

export const appendFileAsync = async (filePath, fileContentString) => {
  return new Promise((resolve, reject) => {
    fs.appendFile(filePath, fileContentString, (err) => {
      if (err) {
        console.log(
          `ERROR, while appending message '${fileContentString}' to a file at ${filePath} - error trace: ${err}`
        );
        reject(); // Reject with the error
      } else {
        resolve(); // Resolve without any value
      }
    });
  });
};

export const appendFile = (filePath, fileContentString) => {
  try {
    fs.appendFileSync(filePath, fileContentString);
  } catch (err) {
    log(
      `ERROR, while synchronously appending message '${fileContentString}' to a file at ${filePath} - error trace: ${err}`
    );
  }
};

export const appendFileFromTop = (filePath, fileContentString) => {
  try {
    const existingContent = fs.readFileSync(filePath, "utf-8");
    const updatedContent = fileContentString + existingContent;

    writeFile(filePath, updatedContent);
  } catch (err) {
    log(
      `ERROR, while synchronously appending message '${fileContentString}' to the top-line of the file at ${filePath} - error trace: ${err}`
    );
  }
};

export const csvToArray = (filePath) => {
  return new Promise((resolve) => {
    const result = [];
    fs.createReadStream(filePath)
      .on("error", (err) => {
        log(
          `ERROR, while reading csv file at ${filePath} - error trace: ${err}`
        );
        resolve([]);
      })
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
        resolve([]);
      });
  });
};

export const readDir = (dirPath) => {
  return new Promise((resolve) => {
    fs.readdir(dirPath, (err, files) => {
      const logMessage = err
        ? `ERROR, while reading files from ${dirPath} - error trace: ${err}`
        : `SUCCESS, while reading files from ${dirPath}`;

      if (err) {
        log(logMessage);
        resolve([]);
      }
      resolve(files);
    });
  });
};

export const readJsonFileSync = (filePath) => {
  try {
    const jsonData = fs.readFileSync(filePath, "utf-8");
    const data = JSON.parse(jsonData);
    return data;
  } catch (err) {
    log(
      `ERROR, while reading a json file at ${filePath} - error trace: ${err}`
    );
  }
};

export const mergeJsonFiles = async (dirPath) => {
  let combinedData = [];
  const fileNames = await readDir(dirPath);
  fileNames.forEach((fileName, index) => {
    if (path.extname(fileName) === ".json") {
      const filePath = path.join(dirPath, fileName);
      const data = readJsonFileSync(filePath);

      if (data) combinedData.push(data);

      if (
        combinedData.length === JSON_OBJECT_LIMIT_PER_FILE ||
        index === fileNames.length - 1
      ) {
        try {
          fs.writeFileSync(
            `commitIDs/dataset-${nanoid()}.json`,
            JSON.stringify(combinedData, null, 4)
          );
        } catch (err) {
          log(
            `ERROR, while writing combined JSON file, resulting from ${dirPath} - error trace: ${err}`
          );
        }
        combinedData = [];
      }
    }
  });
};
