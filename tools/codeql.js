import { createNewLogFile, log } from "../services/logger.js";
import {
  makeDir,
  writeFile,
  csvToArray,
  appendFileFromTop,
} from "../services/file.js";

createNewLogFile();

const csvHeader =
  "name,description,severity,message,path,startLine,startColumn,endLine,endColumn\n";

export class CodeQl {
  convertCsvToFormattedResult = async (filePath) => {
    // appendFileFromTop(filePath, csvHeader);
    const formattedResults = [];
    await makeDir("./formattedResults");

    const issues = await csvToArray(filePath);

    for (const issue of issues) {
      const formattedResult = {
        name: issue.name,
        description: issue.description,
        vulPath: issue.path.replace("/", ""),
        lineNumber: issue.startLine ? parseInt(issue.startLine) : undefined,
        scope: {
          start: issue.startLine ? parseInt(issue.startLine) : undefined,
          end: issue.endLine ? parseInt(issue.endLine) : undefined,
        },
        type: issue.severity,
        key: "",
        rule: "",
        severity: issue.severity,
        message: issue.message,
        effort: "",
        tags: [],
        quickFixAvailable: "no information",
        properties: {},
      };

      formattedResults.push(formattedResult);
    }

    writeFile(
      `./formattedResults/formattedResult-codeql.json`,
      JSON.stringify(formattedResults, null, 4)
    );
  };
}
