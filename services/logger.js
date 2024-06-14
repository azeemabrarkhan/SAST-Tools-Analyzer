import { getTimeStamp } from "../utils/timeData.js";
import { deleteFile, appendFileAsync } from "./file.js";

const currentDir = process.cwd();
let logFilePath;
let lineNumber;

export const createNewLogFile = () => {
  logFilePath = `${currentDir}/log-${getTimeStamp()}.txt`;
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
