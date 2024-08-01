import Analyzer from "./analyzer.js";
import {
  makeDir,
  readJsonFileSync,
  writeFile,
  readFile,
} from "./services/file.js";
import { findAllIndexes } from "./utils/arryas.js";

export default class Combiner {
  found;
  notFound;
  notRecognizedPatches;
  recordsToAnalyze;
  analyzer;
  analysisLevel;
  toolOrLogicName;
  availableTools;

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
    } else if (this.analysisLevel === "function") {
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
    } else {
      return this.recordsToAnalyze.length;
    }
  };

  setFoundAndNotFound = (results) => {
    this.found = [];
    this.notFound = [];
    for (const resultSlice of results.filter((r) =>
      r.vulPath.startsWith("vul/")
    )) {
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
              // todo
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
              // todo
              this.notFound[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          }
          break;

        case "function":
          if (actualVulsInTheCurrentFile.length === 0) {
            indexOfAlreadyFoundOrNotFound = this.notFound.findIndex(
              (r) => r.vulPath === resultSlice.vulPath
            );
            if (indexOfAlreadyFoundOrNotFound < 0) {
              this.notFound.push(resultSlice);
            } else {
              // todo
              this.notFound[indexOfAlreadyFoundOrNotFound].similarResults.push(
                resultSlice
              );
            }
          } else {
            if (
              actualVulsInTheCurrentFile.find(
                (v) =>
                  this.getFunctionNameWithLineNumer(
                    v.functionsInVul,
                    v.lineNumber
                  ) ===
                  this.getFunctionNameWithLineNumer(
                    v.functionsInVul,
                    resultSlice.lineNumber
                  )
              )
            ) {
              indexOfAlreadyFoundOrNotFound = this.found.findIndex(
                (r) =>
                  r.vulPath === resultSlice.vulPath &&
                  this.getFunctionNameWithLineNumer(
                    actualVulsInTheCurrentFile[0].functionsInVul,
                    r.lineNumber
                  ) ===
                    this.getFunctionNameWithLineNumer(
                      actualVulsInTheCurrentFile[0].functionsInVul,
                      resultSlice.lineNumber
                    )
              );
              if (indexOfAlreadyFoundOrNotFound < 0) {
                this.found.push(resultSlice);
              } else {
                // todo
                this.found[indexOfAlreadyFoundOrNotFound].similarResults.push(
                  resultSlice
                );
              }
            } else {
              indexOfAlreadyFoundOrNotFound = this.notFound.findIndex(
                (r) =>
                  r.vulPath === resultSlice.vulPath &&
                  this.getFunctionNameWithLineNumer(
                    actualVulsInTheCurrentFile[0].functionsInVul,
                    r.lineNumber
                  ) ===
                    this.getFunctionNameWithLineNumer(
                      actualVulsInTheCurrentFile[0].functionsInVul,
                      resultSlice.lineNumber
                    )
              );
              if (indexOfAlreadyFoundOrNotFound < 0) {
                this.notFound.push(resultSlice);
              } else {
                // todo
                this.notFound[
                  indexOfAlreadyFoundOrNotFound
                ].similarResults.push(resultSlice);
              }
            }
          }
          break;

        case "line":
          if (
            actualVulsInTheCurrentFile.find(
              (v) => v.lineNumber === resultSlice.lineNumber
            )
          ) {
            this.found.push(resultSlice);
          } else {
            this.notFound.push(resultSlice);
          }
          break;
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
      }

      for (let i = 1; i < toolResults.length && isVulnerable; i++) {
        const toolResult = toolResults[i];

        let indexOfCurrentTool = -1;

        switch (this.analysisLevel) {
          case "file":
            indexOfCurrentTool = toolResult.findIndex(
              (result) => result.vulPath === vul.vulPath
            );
            isVulnerable = indexOfCurrentTool >= 0 && indexOfAlreadyFound < 0;
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
            isVulnerable = indexOfCurrentTool >= 0 && indexOfAlreadyFound < 0;
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

      if (indexOfAlreadyFound >= 0) {
        // todo
        results[indexOfAlreadyFound].similarResults.push(vul);
      }

      if (isVulnerable) {
        results.push(vul);
      }
    }

    this.processResults(results);
  };

  withOrLogic = () => {
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
                // todo
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
                // todo
                results[indexOfAlreadyFound].similarResults.push(result);
              }
              break;

            case "line":
              indexOfAlreadyFound = results.findIndex(
                (r) =>
                  r.vulPath === result.vulPath &&
                  r.lineNumber === result.lineNumber &&
                  r.toolName !== result.toolName
              );
              if (indexOfAlreadyFound >= 0) {
                // todo
                const allIndexes = findAllIndexes(
                  results,
                  (r) =>
                    r.vulPath === result.vulPath &&
                    r.lineNumber === result.lineNumber &&
                    r.toolName !== result.toolName
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
    this.saveResultFile();
    this.analyzer.evaluateResult(
      this.found.length,
      this.notFound.length,
      this.notRecognizedPatches.length,
      this.getTotalVulCount()
    );
  };

  saveResultFile = () => {
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
