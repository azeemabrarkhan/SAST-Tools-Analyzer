import { createNewLogFile, log } from "../services/logger.js";
import {
  makeDir,
  writeFile,
  readJsonFileSync,
  appendFileFromTop,
} from "../services/file.js";

createNewLogFile();

const csvHeader =
  "name,description,severity,message,path,startLine,startColumn,endLine,endColumn\n";

export class Snyk {
  convertJsonToFormattedResult = async (filePath) => {
    // appendFileFromTop(filePath, csvHeader);
    const formattedResults = [];
    await makeDir("./formattedResults");

    const runs = (await readJsonFileSync(filePath))?.runs;

    if (runs && runs.length !== 0 && runs[0].results) {
      for (const result of runs[0].results) {
        const { artifactLocation, region } =
          result.locations[0].physicalLocation;

        const formattedResult = {
          name: "",
          description: result.message.text,
          vulPath: artifactLocation.uri,
          lineNumber: region.startLine ? parseInt(region.startLine) : undefined,
          scope: {
            start: region.startLine ? parseInt(region.startLine) : undefined,
            end: region.endLine ? parseInt(region.endLine) : undefined,
          },
          type: result.level,
          key: result.fingerprints[0],
          rule: result.ruleId,
          severity: result.level,
          message: result.message.markdown,
          effort: "",
          tags: [],
          quickFixAvailable: result.properties.isAutofixable ? "yes" : "no",
          properties: result.properties,
        };

        formattedResults.push(formattedResult);
      }
    }

    writeFile(
      `./formattedResults/formattedResult-snyk.json`,
      JSON.stringify(formattedResults, null, 4)
    );
  };
}
