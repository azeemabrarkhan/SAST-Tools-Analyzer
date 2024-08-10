import Analyzer from "./analyzer.js";
import { makeDir, readJsonFileSync, writeFile } from "./services/file.js";
import { findAllIndexes } from "./services/arryas.js";
import {
  getCWEsCount,
  getDetectedCWEsPercentage,
} from "./services/cweProcessor.js";

export default class Combiner {
  found;
  notFound;
  notRecognizedPatches;
  recordsToAnalyze;
  analyzer;
  analysisLevel;
  toolOrLogicName;
  availableTools;
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
    this.analyzer = new Analyzer();
    this.analysisLevel = "file";
    this.availableTools = [
      { name: process.env.TOOL1_NAME, isActive: true },
      { name: process.env.TOOL2_NAME, isActive: true },
      { name: process.env.TOOL3_NAME, isActive: true },
    ];

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

  getActiveTools = () => {
    return this.availableTools
      .filter((tool) => tool.isActive)
      .map((tool) => tool.name);
  };

  printActiveTools = () => {
    console.log(this.getActiveTools());
  };

  isToolActive = (toolName) => {
    const tool = this.availableTools.find((tool) => tool.name === toolName);
    return tool && tool.isActive;
  };

  activateAllTools = () => {
    this.availableTools = this.availableTools.map((tool) => ({
      ...tool,
      isActive: true,
    }));
  };

  switchTool = (toolName) => {
    const index = this.availableTools.findIndex(
      (tool) => tool.name === toolName
    );
    this.availableTools[index].isActive = !this.availableTools[index].isActive;
  };

  analyzeOnFileLevel = () => {
    this.analysisLevel = "file";
  };

  analyzeOnFunctionLevel = () => {
    this.analysisLevel = "function";
  };

  analyzeOnLineLevel = () => {
    this.analysisLevel = "line";
  };

  getFunctionNameWithLineNumer = (functions, lineNumber) => {
    const fs = functions
      .filter((f) => f.startLine <= lineNumber && f.endLine >= lineNumber)
      .sort((fA, fB) => fB.startLine - fA.startLine);
    return fs[0]?.name ?? lineNumber;
  };

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
              this.getFunctionNameWithLineNumer(
                r.functionsInVul,
                r.lineNumber
              ) ===
                this.getFunctionNameWithLineNumer(
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
          (r) =>
            r.functionsInHierarchicalStructure.filter((f) => f.isVuln).length
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
                this.getFunctionNameWithLineNumer(
                  v.functionsInVul,
                  v.lineNumber
                ) ===
                this.getFunctionNameWithLineNumer(
                  v.functionsInVul,
                  resultSlice.lineNumber
                )
            );
          } else if (
            process.env.RECORDS_TO_ANALYZE === "repositories/javascriptDataset"
          ) {
            const vulFunctionName = this.getFunctionNameWithLineNumer(
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
                this.getFunctionNameWithLineNumer(
                  actualVulsInTheCurrentFile[0]?.functionsInVul ?? [],
                  r.lineNumber
                ) ===
                  this.getFunctionNameWithLineNumer(
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
                this.getFunctionNameWithLineNumer(
                  actualVulsInTheCurrentFile[0]?.functionsInVul ?? [],
                  r.lineNumber
                ) ===
                  this.getFunctionNameWithLineNumer(
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
                  this.getFunctionNameWithLineNumer(
                    r.functionsInFix,
                    resultSlice.lineNumber
                  ) ===
                    this.getFunctionNameWithLineNumer(
                      r.functionsInVul,
                      f.lineNumber
                    )
              )
            )
          ) {
            const alreadyFoundPatchNotRecognizedIndex =
              this.notRecognizedPatches.findIndex(
                (nr) =>
                  nr.vulPath === resultSlice.vulPath &&
                  this.getFunctionNameWithLineNumer(
                    records[0].functionsInFix,
                    nr.lineNumber
                  ) ===
                    this.getFunctionNameWithLineNumer(
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

  evaluateIndividualTool = (toolName) => {
    if (
      process.env.RECORDS_TO_ANALYZE === "repositories/javascriptDataset" &&
      this.analysisLevel === "line"
    ) {
      return;
    }

    if (!this.isToolActive(toolName)) {
      console.log(`The selected tool '${toolName}' is currently disabled\n`);
      return;
    }

    let toolResult;

    switch (toolName) {
      case process.env.TOOL1_NAME:
        toolResult = readJsonFileSync(
          `${process.cwd()}/formattedResults/formattedResult-${
            process.env.TOOL1_NAME
          }.json`
        );
        this.toolOrLogicName = process.env.TOOL1_NAME?.toUpperCase();
        break;

      case process.env.TOOL2_NAME:
        toolResult = readJsonFileSync(
          `${process.cwd()}/formattedResults/formattedResult-${
            process.env.TOOL2_NAME
          }.json`
        );
        this.toolOrLogicName = process.env.TOOL2_NAME?.toUpperCase();
        break;

      case process.env.TOOL3_NAME:
        toolResult = readJsonFileSync(
          `${process.cwd()}/formattedResults/formattedResult-${
            process.env.TOOL3_NAME
          }.json`
        );
        this.toolOrLogicName = process.env.TOOL3_NAME?.toUpperCase();
        break;
    }

    this.processResults(toolResult);
  };

  withAndLogic = () => {
    if (
      process.env.RECORDS_TO_ANALYZE === "repositories/javascriptDataset" &&
      this.analysisLevel === "line"
    ) {
      return;
    }

    const fileNames = this.getActiveTools().map(
      (selectedToolName) => `formattedResult-${selectedToolName}.json`
    );
    if (fileNames.length === 1) {
      console.log(
        "Only one tool is currently active - can not combine results with AND logic\n"
      );
      return;
    }
    this.toolOrLogicName = "AND LOGIC";
    let toolResults = [];
    const results = [];

    for (let i = 0; i < fileNames.length; i++) {
      const toolResult = readJsonFileSync(
        `${process.cwd()}/formattedResults/${fileNames[i]}`
      );
      if (toolResult) toolResults.push(toolResult);
    }

    for (const vul of toolResults[0]) {
      let isVulnerable = true;

      const functionsInTheCurrentFile =
        this.recordsToAnalyze.find((record) => record.vulPath === vul.vulPath)
          ?.functionsInVul ?? [];

      let indexOfAlreadyFound = -1;

      switch (this.analysisLevel) {
        case "file":
          indexOfAlreadyFound = results.findIndex(
            (r) => r.vulPath === vul.vulPath
          );
          break;
        case "function":
          indexOfAlreadyFound = results.findIndex(
            (r) =>
              r.vulPath === vul.vulPath &&
              this.getFunctionNameWithLineNumer(
                functionsInTheCurrentFile,
                r.lineNumber
              ) ===
                this.getFunctionNameWithLineNumer(
                  functionsInTheCurrentFile,
                  vul.lineNumber
                )
          );
          break;
        case "line":
          indexOfAlreadyFound = results.findIndex(
            (r) => r.vulPath === vul.vulPath && r.lineNumber === vul.lineNumber
          );
          break;
      }

      for (let i = 1; i < toolResults.length && isVulnerable; i++) {
        const toolResult = toolResults[i];

        let indexOfCurrentTool = -1;

        switch (this.analysisLevel) {
          case "file":
            indexOfCurrentTool = toolResult.findIndex(
              (result) => result.vulPath === vul.vulPath
            );
            isVulnerable = indexOfCurrentTool >= 0;
            if (indexOfCurrentTool >= 0) {
              vul.similarResults.push(toolResult[indexOfCurrentTool]);
            }
            break;

          case "function":
            indexOfCurrentTool = toolResult.findIndex(
              (v) =>
                v.vulPath === vul.vulPath &&
                this.getFunctionNameWithLineNumer(
                  functionsInTheCurrentFile,
                  v.lineNumber
                ) ===
                  this.getFunctionNameWithLineNumer(
                    functionsInTheCurrentFile,
                    vul.lineNumber
                  )
            );
            isVulnerable = indexOfCurrentTool >= 0;
            if (indexOfCurrentTool >= 0) {
              vul.similarResults.push(toolResult[indexOfCurrentTool]);
            }
            break;

          case "line":
            indexOfCurrentTool = toolResult.findIndex(
              (v) =>
                v.vulPath === vul.vulPath && v.lineNumber === vul.lineNumber
            );
            isVulnerable = indexOfCurrentTool >= 0;
            if (indexOfCurrentTool >= 0) {
              vul.similarResults.push(toolResult[indexOfCurrentTool]);
            }
            break;
        }
      }

      if (isVulnerable) {
        if (indexOfAlreadyFound >= 0) {
          // todo
          results[indexOfAlreadyFound].similarResults.push(vul);
        } else {
          results.push(vul);
        }
      }
    }

    this.processResults(results);
  };

  withOrLogic = () => {
    if (
      process.env.RECORDS_TO_ANALYZE === "repositories/javascriptDataset" &&
      this.analysisLevel === "line"
    ) {
      return;
    }

    const fileNames = this.getActiveTools().map(
      (selectedToolName) => `formattedResult-${selectedToolName}.json`
    );
    if (fileNames.length === 1) {
      console.log(
        "Only one tool is currently active - can not combine results with OR logic\n"
      );
      return;
    }
    this.toolOrLogicName = "OR LOGIC";
    let results = [];

    for (let i = 0; i < fileNames.length; i++) {
      const toolResult = readJsonFileSync(
        `${process.cwd()}/formattedResults/${fileNames[i]}`
      );
      if (toolResult) {
        for (const result of toolResult) {
          let indexOfAlreadyFound;

          const functionsInTheCurrentFile =
            this.recordsToAnalyze.find(
              (record) => record.vulPath === result.vulPath
            )?.functionsInVul ?? [];

          switch (this.analysisLevel) {
            case "file":
              indexOfAlreadyFound = results.findIndex(
                (r) => r.vulPath === result.vulPath
              );
              if (indexOfAlreadyFound >= 0) {
                results[indexOfAlreadyFound].similarResults.push(result);
              }
              break;

            case "function":
              indexOfAlreadyFound = results.findIndex(
                (r) =>
                  r.vulPath === result.vulPath &&
                  this.getFunctionNameWithLineNumer(
                    functionsInTheCurrentFile,
                    r.lineNumber
                  ) ===
                    this.getFunctionNameWithLineNumer(
                      functionsInTheCurrentFile,
                      result.lineNumber
                    )
              );
              if (indexOfAlreadyFound >= 0) {
                results[indexOfAlreadyFound].similarResults.push(result);
              }
              break;

            case "line":
              indexOfAlreadyFound = results.findIndex(
                (r) =>
                  r.vulPath === result.vulPath &&
                  r.lineNumber === result.lineNumber
              );
              if (indexOfAlreadyFound >= 0) {
                const allIndexes = findAllIndexes(
                  results,
                  (r) =>
                    r.vulPath === result.vulPath &&
                    r.lineNumber === result.lineNumber
                );
                for (const index of allIndexes) {
                  results[index].similarResults.push(result);
                }
              }
              break;
          }

          if (indexOfAlreadyFound < 0) {
            results.push(result);
          }
        }
      }
    }

    this.processResults(results);
  };

  processResults = (results) => {
    if (
      this.toolOrLogicName === "OR LOGIC" ||
      this.toolOrLogicName === "AND LOGIC"
    ) {
      this.printActiveTools();
    }
    console.log(
      `***${this.toolOrLogicName}*** - ${this.analysisLevel.toUpperCase()}`
    );
    this.setFoundAndNotFound(results);
    this.setNotRecognizedPatches(results);
    this.saveResultFiles();
    this.analyzer.evaluateResult(
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
      path += `${this.getActiveTools().join("_")}`;
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
    return [
      ...getSortedTypedIssues(combinedResults, "error"),
      // ...getSortedTypedIssues(combinedResults, "warning"),
    ];
  };

  runCombinerByTool = (toolName) => {
    if (!this.isToolActive(toolName)) {
      console.log(`The selected tool '${toolName}' is currently disabled\n`);
      return;
    }

    this.analyzeOnFileLevel();
    this.evaluateIndividualTool(toolName);

    this.analyzeOnFunctionLevel();
    this.evaluateIndividualTool(toolName);

    this.analyzeOnLineLevel();
    this.evaluateIndividualTool(toolName);
  };

  runCombinerByLogic = (logicFunction) => {
    if (this.getActiveTools().length === 1) {
      console.log(
        "Only one tool is currently active - can not combine results\n"
      );
      return;
    }

    this.analyzeOnFileLevel();
    logicFunction();

    this.analyzeOnFunctionLevel();
    logicFunction();

    this.analyzeOnLineLevel();
    logicFunction();
  };

  runCombinerByGranularityLevel = () => {
    this.evaluateIndividualTool(process.env.TOOL1_NAME);
    this.evaluateIndividualTool(process.env.TOOL2_NAME);
    this.evaluateIndividualTool(process.env.TOOL3_NAME);

    this.withOrLogic();
    this.withAndLogic();
  };

  runAllCombinations = () => {
    this.evaluateIndividualTool(process.env.TOOL1_NAME);
    this.evaluateIndividualTool(process.env.TOOL2_NAME);
    this.evaluateIndividualTool(process.env.TOOL3_NAME);

    this.withOrLogic();
    this.withAndLogic();

    this.switchTool(process.env.TOOL1_NAME);
    this.withOrLogic();
    this.withAndLogic();

    this.switchTool(process.env.TOOL2_NAME);
    this.switchTool(process.env.TOOL1_NAME);
    this.withOrLogic();
    this.withAndLogic();

    this.switchTool(process.env.TOOL3_NAME);
    this.switchTool(process.env.TOOL2_NAME);
    this.withOrLogic();
    this.withAndLogic();

    this.switchTool(process.env.TOOL3_NAME);
  };
}
