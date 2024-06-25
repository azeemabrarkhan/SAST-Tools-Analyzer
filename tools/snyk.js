import {
  makeDir,
  writeFile,
  readJsonFileSync,
  readFile,
} from "../services/file.js";
import { getSingleLineFromString } from "../utils/text.js";

export class Snyk {
  convertJsonToFormattedResult = async () => {
    const filePath = `${process.env.FILES_BASE_PATH}/${process.env.SNYK_RESULT_FILENAME}`;

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
          type: "",
          key: result.fingerprints[0],
          rule: result.ruleId,
          severity: result.level,
          message: result.message.markdown,
          effort: "",
          tags: [],
          quickFixAvailable: result.properties.isAutofixable ? "yes" : "no",
          toolName: "snyk",
          properties: result.properties,
          similarResults: [],
        };

        formattedResult.foundVulLine = getSingleLineFromString(
          readFile(`${process.env.FILES_BASE_PATH}/${formattedResult.vulPath}`),
          formattedResult.lineNumber
        );

        formattedResults.push(formattedResult);
      }
    }

    writeFile(
      `./formattedResults/formattedResult-snyk.json`,
      JSON.stringify(formattedResults, null, 4)
    );
  };
}
