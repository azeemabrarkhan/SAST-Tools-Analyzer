import { deleteFile, appendFileAsync } from "./file.js";

const currentDir = process.cwd();
let logFilePath;
let lineNumber;

export const createNewLogFile = () => {
  const date = new Date();
  logFilePath = `${currentDir}\\log-${date.toDateString()} - HH MM SS ${date.getHours()} ${date.getMinutes()} ${date.getSeconds()}.txt`;
  lineNumber = 1;
};

export const clearLog = () => {
  deleteFile(logFilePath, "");
  lineNumber = 1;
};

export const log = async (message) => {
  await appendFileAsync(logFilePath, `\n${lineNumber} - ${message}`);
  lineNumber++;
};

createNewLogFile();
