import { deleteFile, appendFileAsync } from "./file.js";

const currentDir = process.cwd();
const logFilePath = `${currentDir}\\log.txt`;

let lineNumber = 1;

export const clearLog = () => {
  deleteFile(logFilePath, "");
};

export const log = (message) => {
  appendFileAsync(logFilePath, `\n${lineNumber} - ${message}`);
  lineNumber++;
};
