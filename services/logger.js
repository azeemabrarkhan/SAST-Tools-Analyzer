import { nanoid } from "nanoid";
import { deleteFile, appendFileAsync } from "./file.js";

const currentDir = process.cwd();
let logFilePath;

let lineNumber = 1;

export const createNewLogFile = () => {
  logFilePath = `${currentDir}\\log-${nanoid()}.txt`;
};

export const clearLog = () => {
  deleteFile(logFilePath, "");
};

export const log = (message) => {
  appendFileAsync(logFilePath, `\n${lineNumber} - ${message}`);
  lineNumber++;
};
