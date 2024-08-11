import Analyzer from "./analyzer.js";
import { readJsonFileSync } from "./services/file.js";
import { findAllIndexes } from "./services/arryas.js";
import { getFunctionNameWithLineNumer } from "./services/functions.js";

export default class Combiner {
  analyzer;
  analysisLevel;
  toolOrLogicName;
  availableTools;
  recordsToAnalyze;

  constructor() {
    this.analyzer = new Analyzer();
    this.analysisLevel = "file";
    this.toolOrLogicName = "";
    this.availableTools = [
      { name: process.env.TOOL1_NAME, isActive: true },
      { name: process.env.TOOL2_NAME, isActive: true },
      { name: process.env.TOOL3_NAME, isActive: true },
    ];
    this.recordsToAnalyze = readJsonFileSync(
      `${process.cwd()}/${
        process.env.RECORDS_TO_ANALYZE
      }/downloadedRecords.json`
    );
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

    this.callAnalyzer(toolResult);
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
              getFunctionNameWithLineNumer(
                functionsInTheCurrentFile,
                r.lineNumber
              ) ===
                getFunctionNameWithLineNumer(
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
                getFunctionNameWithLineNumer(
                  functionsInTheCurrentFile,
                  v.lineNumber
                ) ===
                  getFunctionNameWithLineNumer(
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

    this.callAnalyzer(results);
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
                  getFunctionNameWithLineNumer(
                    functionsInTheCurrentFile,
                    r.lineNumber
                  ) ===
                    getFunctionNameWithLineNumer(
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

    this.callAnalyzer(results);
  };

  callAnalyzer = (results) => {
    if (
      this.toolOrLogicName === "OR LOGIC" ||
      this.toolOrLogicName === "AND LOGIC"
    ) {
      this.printActiveTools();
    }
    console.log(
      `***${this.toolOrLogicName}*** - ${this.analysisLevel.toUpperCase()}`
    );

    this.analyzer.processResults(
      results,
      this.analysisLevel,
      this.toolOrLogicName,
      this.getActiveTools()
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
