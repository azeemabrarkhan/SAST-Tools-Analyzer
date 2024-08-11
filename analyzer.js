import { makeDir, readJsonFileSync, writeFile } from "./services/file.js";
import {
  getCWEsCount,
  getDetectedCWEsPercentage,
} from "./services/cweProcessor.js";
import { getFunctionNameWithLineNumer } from "./services/functions.js";

export default class Analyzer {
  found;
  notFound;
  notRecognizedPatches;
  recordsToAnalyze;
  analysisLevel;
  toolOrLogicName;
  currentTools;
  totalCWEsCount;

  constructor() {
    this.found = [];
    this.notFound = [];
    this.notRecognizedPatches = [];
    this.recordsToAnalyze = readJsonFileSync(
      `${process.cwd()}/${
        process.env.RECORDS_TO_ANALYZE
      }/downloadedRecords.json`
    );
    this.analysisLevel = "";
    this.toolOrLogicName = "";
    this.currentTools = [];

    if (process.env.RECORDS_TO_ANALYZE === "repositories/ossf") {
      this.totalCWEsCount = getCWEsCount(this.recordsToAnalyze);

      const path = "./output/";
      makeDir(path);

      writeFile(
        `${path}/total_CWEs_count.json`,
        JSON.stringify(this.totalCWEsCount, null, 2)
      );
    }
  }

  getTotalVulCount = () => {
    let recordsToAnalyzeWithoutDuplicates = [];
    if (this.analysisLevel === "file") {
      for (const record of this.recordsToAnalyze) {
        if (
          !recordsToAnalyzeWithoutDuplicates.find(
            (r) => r.vulPath === record.vulPath
          )
        ) {
          recordsToAnalyzeWithoutDuplicates.push(record);
        }
      }
      return recordsToAnalyzeWithoutDuplicates.length;
    } else if (
      this.analysisLevel === "function" &&
      process.env.RECORDS_TO_ANALYZE === "repositories/ossf"
    ) {
      for (const record of this.recordsToAnalyze) {
        if (
          !recordsToAnalyzeWithoutDuplicates.find(
            (r) =>
              r.vulPath === record.vulPath &&
              getFunctionNameWithLineNumer(r.functionsInVul, r.lineNumber) ===
                getFunctionNameWithLineNumer(
                  r.functionsInVul,
                  record.lineNumber
                )
          )
        ) {
          recordsToAnalyzeWithoutDuplicates.push(record);
        }
      }
      return recordsToAnalyzeWithoutDuplicates.length;
    } else if (
      this.analysisLevel === "function" &&
      process.env.RECORDS_TO_ANALYZE === "repositories/javascriptDataset"
    ) {
      return this.recordsToAnalyze
        .map(
          (r) => r.innerMostVulnerableFunctions.filter((f) => f.isVuln).length
        )
        .reduce((acc, c) => acc + c, 0);
    } else {
      return this.recordsToAnalyze.length;
    }
  };

  setFoundAndNotFound = (results) => {
    this.found = [];
    this.notFound = [];

    const vulResults =
      process.env.RECORDS_TO_ANALYZE === "repositories/ossf"
        ? results.filter((r) => r.vulPath.startsWith("vul/"))
        : results;

    for (const resultSlice of vulResults) {
      const actualVulsInTheCurrentFile = this.recordsToAnalyze.filter(
        (record) => record.vulPath === resultSlice.vulPath
      );

      let indexOfAlreadyFoundOrNotFound = -1;

      switch (this.analysisLevel) {
        case "file":
          if (actualVulsInTheCurrentFile.length > 0) {
            indexOfAlreadyFoundOrNotFound = this.found.findIndex(
              (r) => r.vulPath === resultSlice.vulPath
            );
            if (indexOfAlreadyFoundOrNotFound < 0) {
              this.found.push(resultSlice);
            } else {
              this.found[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          } else {
            indexOfAlreadyFoundOrNotFound = this.notFound.findIndex(
              (r) => r.vulPath === resultSlice.vulPath
            );
            if (indexOfAlreadyFoundOrNotFound < 0) {
              this.notFound.push(resultSlice);
            } else {
              this.notFound[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          }
          break;

        case "function":
          let matchFunctionFound;
          if (process.env.RECORDS_TO_ANALYZE === "repositories/ossf") {
            matchFunctionFound = actualVulsInTheCurrentFile.find(
              (v) =>
                getFunctionNameWithLineNumer(v.functionsInVul, v.lineNumber) ===
                getFunctionNameWithLineNumer(
                  v.functionsInVul,
                  resultSlice.lineNumber
                )
            );
          } else if (
            process.env.RECORDS_TO_ANALYZE === "repositories/javascriptDataset"
          ) {
            const vulFunctionName = getFunctionNameWithLineNumer(
              actualVulsInTheCurrentFile[0]?.functionsInVul ?? [],
              resultSlice.lineNumber
            );

            matchFunctionFound =
              typeof vulFunctionName === "string"
                ? actualVulsInTheCurrentFile[0]?.functionsInVul.find(
                    (f) => f.name === vulFunctionName
                  ).isVuln
                : false;
          }
          if (matchFunctionFound) {
            indexOfAlreadyFoundOrNotFound = this.found.findIndex(
              (r) =>
                r.vulPath === resultSlice.vulPath &&
                getFunctionNameWithLineNumer(
                  actualVulsInTheCurrentFile[0]?.functionsInVul ?? [],
                  r.lineNumber
                ) ===
                  getFunctionNameWithLineNumer(
                    actualVulsInTheCurrentFile[0]?.functionsInVul ?? [],
                    resultSlice.lineNumber
                  )
            );
            if (indexOfAlreadyFoundOrNotFound < 0) {
              this.found.push(resultSlice);
            } else {
              this.found[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          } else {
            indexOfAlreadyFoundOrNotFound = this.notFound.findIndex(
              (r) =>
                r.vulPath === resultSlice.vulPath &&
                getFunctionNameWithLineNumer(
                  actualVulsInTheCurrentFile[0]?.functionsInVul ?? [],
                  r.lineNumber
                ) ===
                  getFunctionNameWithLineNumer(
                    actualVulsInTheCurrentFile[0]?.functionsInVul ?? [],
                    resultSlice.lineNumber
                  )
            );
            if (indexOfAlreadyFoundOrNotFound < 0) {
              this.notFound.push(resultSlice);
            } else {
              this.notFound[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          }
          break;

        case "line":
          const actualVulsInTheCurrentFileOnSameLine =
            actualVulsInTheCurrentFile.find(
              (v) => v.lineNumber === resultSlice.lineNumber
            );
          if (actualVulsInTheCurrentFileOnSameLine) {
            resultSlice.CWEs = actualVulsInTheCurrentFileOnSameLine.CWEs;

            indexOfAlreadyFoundOrNotFound = this.found.findIndex(
              (r) =>
                r.vulPath === resultSlice.vulPath &&
                r.lineNumber === resultSlice.lineNumber
            );
            if (indexOfAlreadyFoundOrNotFound < 0) {
              this.found.push(resultSlice);
            } else {
              this.found[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          } else {
            indexOfAlreadyFoundOrNotFound = this.notFound.findIndex(
              (r) =>
                r.vulPath === resultSlice.vulPath &&
                r.lineNumber === resultSlice.lineNumber
            );
            if (indexOfAlreadyFoundOrNotFound < 0) {
              this.notFound.push(resultSlice);
            } else {
              this.notFound[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          }
          break;
      }
    }

    if (process.env.RECORDS_TO_ANALYZE === "repositories/ossf") {
      for (const resultSlice of results.filter((r) =>
        r.vulPath.startsWith("clean/")
      )) {
        const indexOfAlreadyFoundOrNotFound = this.notFound.findIndex(
          (r) =>
            r.vulPath === resultSlice.vulPath &&
            r.lineNumber === resultSlice.lineNumber
        );
        if (indexOfAlreadyFoundOrNotFound < 0) {
          this.notFound.push(resultSlice);
        } else {
          this.notFound[indexOfAlreadyFoundOrNotFound].similarResults.push(
            resultSlice
          );
        }
      }
    }
  };

  setNotRecognizedPatches = (results) => {
    this.notRecognizedPatches = [];

    for (const resultSlice of results.filter((r) =>
      r.vulPath.startsWith("fix/")
    )) {
      let records = this.recordsToAnalyze.filter(
        (record) => record.fixPath === resultSlice.vulPath
      );

      switch (this.analysisLevel) {
        case "file":
          if (
            this.found.find((f) => records.find((r) => r.vulPath === f.vulPath))
          ) {
            const alreadyFoundPatchNotRecognizedIndex =
              this.notRecognizedPatches.findIndex(
                (nr) => nr.vulPath === resultSlice.vulPath
              );
            if (alreadyFoundPatchNotRecognizedIndex < 0) {
              this.notRecognizedPatches.push(resultSlice);
            } else {
              this.notRecognizedPatches[
                alreadyFoundPatchNotRecognizedIndex
              ].similarResults.push(resultSlice);
            }
          }
          break;

        case "function":
          if (
            this.found.find((f) =>
              records.find(
                (r) =>
                  r.vulPath === f.vulPath &&
                  getFunctionNameWithLineNumer(
                    r.functionsInFix,
                    resultSlice.lineNumber
                  ) ===
                    getFunctionNameWithLineNumer(r.functionsInVul, f.lineNumber)
              )
            )
          ) {
            const alreadyFoundPatchNotRecognizedIndex =
              this.notRecognizedPatches.findIndex(
                (nr) =>
                  nr.vulPath === resultSlice.vulPath &&
                  getFunctionNameWithLineNumer(
                    records[0].functionsInFix,
                    nr.lineNumber
                  ) ===
                    getFunctionNameWithLineNumer(
                      records[0].functionsInFix,
                      resultSlice.lineNumber
                    )
              );
            if (alreadyFoundPatchNotRecognizedIndex < 0) {
              this.notRecognizedPatches.push(resultSlice);
            } else {
              this.notRecognizedPatches[
                alreadyFoundPatchNotRecognizedIndex
              ].similarResults.push(resultSlice);
            }
          }
          break;

        case "line":
          if (
            this.found.find(
              (f) =>
                f.foundVulLine === resultSlice.foundVulLine &&
                records.find(
                  (r) =>
                    r.vulPath === f.vulPath && r.lineNumber === f.lineNumber
                )
            )
          ) {
            this.notRecognizedPatches.push(resultSlice);
          }
          break;
      }
    }
  };

  processResults = (results, analysisLevel, toolOrLogicName, currentTools) => {
    this.analysisLevel = analysisLevel;
    this.toolOrLogicName = toolOrLogicName;
    this.currentTools = currentTools;

    this.setFoundAndNotFound(results);
    this.setNotRecognizedPatches(results);
    this.saveResultFiles();
    this.calculatePerformanceMetrics(
      this.found.length,
      this.notFound.length,
      this.notRecognizedPatches.length,
      this.getTotalVulCount()
    );
  };

  saveResultFiles = () => {
    let path = `./output/${this.toolOrLogicName}/`;
    if (
      this.toolOrLogicName === "OR LOGIC" ||
      this.toolOrLogicName === "AND LOGIC"
    ) {
      path += `${this.currentTools.join("_")}`;
    }
    makeDir(path);
    writeFile(
      `${path}/${this.analysisLevel}_true_positives.json`,
      JSON.stringify(this.found, null, 4)
    );
    writeFile(
      `${path}/${this.analysisLevel}_false_positives.json`,
      JSON.stringify(this.notFound, null, 4)
    );
    writeFile(
      `${path}/${this.analysisLevel}_not_recognized_patches.json`,
      JSON.stringify(this.notRecognizedPatches, null, 4)
    );

    const priorityIssues = this.getPriorityIssues();
    console.log(
      `Number of important issues with high priority: ${priorityIssues.length}`
    );

    writeFile(
      `${path}/${this.analysisLevel}_important_sorted_results.json`,
      JSON.stringify(priorityIssues, null, 4)
    );

    if (this.totalCWEsCount && this.analysisLevel === "line") {
      const detectedCWEsCount = getCWEsCount(this.found);
      const detectedCWEsPercentage = getDetectedCWEsPercentage(
        this.totalCWEsCount,
        detectedCWEsCount
      );

      writeFile(
        `${path}/${this.analysisLevel}_detected_CWEs_count.json`,
        JSON.stringify(detectedCWEsCount, null, 2)
      );

      writeFile(
        `${path}/${this.analysisLevel}_detected_CWEs_percentage.json`,
        JSON.stringify(detectedCWEsPercentage, null, 2)
      );
    }
  };

  getPriorityIssues = () => {
    const getSortedTypedIssues = (records, type) => {
      const typedFilteredIssues = records.filter((r) => r.alertType === type);
      const sortedSnyKIssues = typedFilteredIssues
        .filter((r) => r.toolName === "snyk")
        .sort(
          (a, b) => b.properties.priorityScore - a.properties.priorityScore
        );
      const otherIssues = typedFilteredIssues.filter(
        (r) => r.toolName !== "snyk"
      );

      const sortedOtherIssues = otherIssues.sort((a, b) => {
        // Sort by severity: High, Medium, then others
        const severityOrder = { High: 1, Medium: 2, Low: 3 };
        const severityA = severityOrder[a.severity] || 4;
        const severityB = severityOrder[b.severity] || 4;
        if (severityA !== severityB) {
          return severityA - severityB;
        }

        // Sort by quickFixAvailable: yes, no, then others
        const quickFixOrder = { yes: 1, no: 2 };
        const quickFixA = quickFixOrder[a.quickFixAvailable] || 3;
        const quickFixB = quickFixOrder[b.quickFixAvailable] || 3;
        if (quickFixA !== quickFixB) {
          return quickFixA - quickFixB;
        }

        // Sort by effort with minimum number first
        const getEffortInMinutes = (effort) => {
          if (!effort) return Infinity;
          const intMins = parseInt(effort);
          return intMins || Infinity;
        };

        return getEffortInMinutes(a.effort) - getEffortInMinutes(b.effort);
      });

      return [...sortedSnyKIssues, ...sortedOtherIssues];
    };

    const combinedResults = [...this.found, ...this.notFound];
    return [...getSortedTypedIssues(combinedResults, "error")];
  };

  calculatePerformanceMetrics = (
    found,
    notFound,
    notRecognizedPatches,
    totalVulnerabilities
  ) => {
    // found = Hits that are included in the known vul set
    // notFound = Hits that are not included in the known vul set

    const tp = found;
    const fp = notFound;
    const fn = totalVulnerabilities - tp;

    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);
    const f1 = 2 * ((precision * recall) / (precision + recall));

    console.log("Total Vulnerabilities", totalVulnerabilities);
    console.log("Total Findings ", tp + fp);
    console.log("True Positive ", tp);
    console.log("False Positive ", fp);
    console.log("False Negative ", fn);
    console.log("Not recognized patches ", notRecognizedPatches);
    console.log("Precision ", precision);
    console.log("Recall ", recall);
    console.log("F1 Score  ", f1);
    console.log("");
  };
}
