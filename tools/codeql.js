import {
  makeDir,
  writeFile,
  csvToArray,
  appendFileFromTop,
  readFile,
} from "../services/file.js";
import { getSingleLineFromString } from "../utils/text.js";

const csvHeader =
  "name,description,severity,message,path,startLine,startColumn,endLine,endColumn\n";

export class CodeQl {
  convertCsvToFormattedResult = async () => {
    const filePath = `${process.env.FILES_BASE_PATH}/${process.env.CODEQL_RESULT_FILENAME}`;

    if (!readFile(filePath).startsWith(csvHeader)) {
      appendFileFromTop(filePath, csvHeader);
    }

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
        type: "",
        key: "",
        rule: "",
        severity: issue.severity,
        message: issue.message,
        effort: "",
        tags: [],
        quickFixAvailable: "no information",
        toolName: "codeql",
        properties: {},
        similarResults: [],
      };

      formattedResult.foundVulLine = getSingleLineFromString(
        readFile(`${process.env.FILES_BASE_PATH}/${formattedResult.vulPath}`),
        formattedResult.lineNumber
      );

      formattedResults.push(formattedResult);
    }

    writeFile(
      `./formattedResults/formattedResult-codeql.json`,
      JSON.stringify(formattedResults, null, 4)
    );
  };
}
