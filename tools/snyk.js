import {
  makeDir,
  writeFile,
  readJsonFileSync,
  readFile,
} from "../services/file.js";
import { getSingleLineFromString } from "../services/text.js";

export class Snyk {
  severitiesRecords;

  constructSeveritiesRecordsFromLogFile = () => {
    const logFilePath = `${process.env.FILES_BASE_PATH}/${process.env.SNYK_LOG_FILENAME}`;

    const logFileText = readFile(logFilePath)
      .split("\r\n")
      .filter((r) => r);

    const severityLines = logFileText.filter((r) => r.includes("✗"));
    const pathLines = logFileText.filter((r) => r.includes("Path:"));
    const infoLines = logFileText.filter((r) => r.includes("Info:"));

    const results = [];

    if (
      severityLines.length === pathLines.length &&
      pathLines.length === infoLines.length
    ) {
      for (let i = 0; i < severityLines.length; i++) {
        const severityLine = severityLines[i].split("]");
        const pathLine = pathLines[i].split("Path:")[1];
        results.push({
          name: severityLine[1].trim(),
          severity: severityLine[0].split("[")[1],
          vulPath: pathLine.split(", line")[0].trim(),
          lineNumber: parseInt(pathLine.split(", line")[1]),
          description: infoLines[i].split("Info:")[1].trim(),
        });
      }
    }

    return results;
  };

  convertJsonToFormattedResult = async () => {
    this.severitiesRecords = this.constructSeveritiesRecordsFromLogFile();

    const resultsFilePath = `${process.env.FILES_BASE_PATH}/${process.env.SNYK_RESULT_FILENAME}`;

    const formattedResults = [];
    await makeDir("./formattedResults");

    const runs = (await readJsonFileSync(resultsFilePath))?.runs;

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
          alertType: result.level,
          severity: "",
          message: result.message.markdown,
          effort: "",
          tags: [],
          quickFixAvailable: result.properties.isAutofixable ? "yes" : "no",
          toolName: "snyk",
          properties: result.properties,
          similarResults: [],
          CWEs: [],
        };

        const currentSeverityRecord = this.severitiesRecords.find(
          (record) =>
            record.vulPath === formattedResult.vulPath &&
            record.lineNumber === formattedResult.lineNumber &&
            record.description === formattedResult.description
        );

        if (currentSeverityRecord) {
          formattedResult.name = currentSeverityRecord.name;
          formattedResult.severity = currentSeverityRecord.severity;
        }

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
