import Analyzer from "./analyzer.js";
import { readJsonFileSync, readDir } from "./services/file.js";

export default class Combiner {
  found;
  notFound;
  metaData;
  analyzer;
  analysisLevel;
  selectedToolsNames;

  constructor() {
    this.found = [];
    this.notFound = [];
    this.metaData = readJsonFileSync(
      `${process.cwd()}\\repositories\\ossf\\metaData.json`
    );
    this.analyzer = new Analyzer();
    this.analysisLevel = "file";
    this.selectedToolsNames = ["codeql", "sonarqube", "snyk"];
  }

  viewSelectedTools = () => {
    console.log(this.selectedToolsNames);
  };

  selectTool = (toolName) => {
    if (!this.selectedToolsNames.includes(toolName)) {
      this.selectedToolsNames.push(toolName);
    }
  };

  deselectTool = (toolName) => {
    this.selectedToolsNames = this.selectedToolsNames.filter(
      (selectedToolName) => selectedToolName !== toolName
    );
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
    return fs[0]?.name;
  };

  getTotalVulCount = () => {
    let metaRecordsWithoutDuplicates = [];
    if (this.analysisLevel === "file") {
      for (const metaSlice of this.metaData) {
        if (
          !metaRecordsWithoutDuplicates.find(
            (r) => r.vulPath === metaSlice.vulPath
          )
        ) {
          metaRecordsWithoutDuplicates.push(metaSlice);
        }
      }
      return metaRecordsWithoutDuplicates.length;
    } else if (this.analysisLevel === "function") {
      for (const metaSlice of this.metaData) {
        if (
          !metaRecordsWithoutDuplicates.find(
            (r) =>
              r.vulPath === metaSlice.vulPath &&
              this.getFunctionNameWithLineNumer(
                r.functionsInVul,
                r.lineNumber
              ) ===
                this.getFunctionNameWithLineNumer(
                  r.functionsInVul,
                  metaSlice.lineNumber
                )
          )
        ) {
          metaRecordsWithoutDuplicates.push(metaSlice);
        }
      }
      return metaRecordsWithoutDuplicates.length;
    } else {
      return this.metaData.length;
    }
  };

  setFoundAndNotFound = (results) => {
    this.found = [];
    this.notFound = [];
    for (const resultSlice of results) {
      const actualVulsInTheCurrentFile = this.metaData.filter(
        (metaSlice) => metaSlice.vulPath === resultSlice.vulPath
      );
      switch (this.analysisLevel) {
        case "file":
          if (
            actualVulsInTheCurrentFile.length > 0 &&
            !this.found.find((r) => r.vulPath === resultSlice.vulPath)
          ) {
            this.found.push(resultSlice);
          } else if (actualVulsInTheCurrentFile.length === 0) {
            this.notFound.push(resultSlice);
          }
          break;

        case "function":
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
            this.found.push(resultSlice);
          } else {
            this.notFound.push(resultSlice);
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

  evaluateIndividualTool = async (toolName) => {
    let toolResult;

    switch (toolName) {
      case "codeql":
        toolResult = readJsonFileSync(
          `${process.cwd()}\\formattedResults\\formattedResult-codeql.json`
        );
        console.log(`***CODE-QL*** - ${this.analysisLevel.toUpperCase()}`);
        break;

      case "sonarqube":
        toolResult = readJsonFileSync(
          `${process.cwd()}\\formattedResults\\formattedResult-sonarqube.json`
        );
        console.log(`***SONAR QUBE*** - ${this.analysisLevel.toUpperCase()}`);
        break;

      case "snyk":
        toolResult = readJsonFileSync(
          `${process.cwd()}\\formattedResults\\formattedResult-snyk.json`
        );
        console.log(`***SNYK*** - ${this.analysisLevel.toUpperCase()}`);
        break;
    }

    this.setFoundAndNotFound(toolResult);
    this.analyzer.evaluateResult(
      this.found,
      this.notFound,
      this.getTotalVulCount()
    );
  };

  withAndLogic = async () => {
    console.log(this.selectedToolsNames);
    // const fileNames = await readDir(`${process.cwd()}\\formattedResults`);
    const fileNames = this.selectedToolsNames.map(
      (selectedToolName) => `formattedResult-${selectedToolName}.json`
    );
    let toolResults = [];
    const results = [];

    for (let i = 0; i < fileNames.length; i++) {
      const toolResult = readJsonFileSync(
        `${process.cwd()}\\formattedResults\\${fileNames[i]}`
      );
      if (toolResult) toolResults.push(toolResult);
    }

    for (const vul of toolResults[0]) {
      let isVulnerable = true;

      for (let i = 1; i < toolResults.length && isVulnerable; i++) {
        const toolResult = toolResults[i];
        const vulInTheSameFileByCurrentTool = toolResult.filter(
          (result) => result.vulPath === vul.vulPath
        );

        const functionsInTheCurrentFile =
          this.metaData.find((metaSlice) => metaSlice.vulPath === vul.vulPath)
            ?.functionsInVul ?? [];

        switch (this.analysisLevel) {
          case "file":
            isVulnerable =
              vulInTheSameFileByCurrentTool.length > 0 &&
              !results.find((r) => r.vulPath === vul.vulPath);
            break;

          case "function":
            isVulnerable = vulInTheSameFileByCurrentTool.find(
              (v) =>
                this.getFunctionNameWithLineNumer(
                  functionsInTheCurrentFile,
                  v.lineNumber
                ) ===
                this.getFunctionNameWithLineNumer(
                  functionsInTheCurrentFile,
                  vul.lineNumber
                )
            )
              ? true
              : false;
            break;

          case "line":
            isVulnerable = vulInTheSameFileByCurrentTool.find(
              (v) => v.lineNumber === vul.lineNumber
            )
              ? true
              : false;
            break;
        }
      }

      if (isVulnerable) {
        results.push(vul);
      }
    }

    console.log(`***AND LOGIC*** - ${this.analysisLevel.toUpperCase()}`);
    this.setFoundAndNotFound(results);
    this.analyzer.evaluateResult(
      this.found,
      this.notFound,
      this.getTotalVulCount()
    );
  };

  withOrLogic = async () => {
    console.log(this.selectedToolsNames);
    // const fileNames = await readDir(`${process.cwd()}\\formattedResults`);
    const fileNames = this.selectedToolsNames.map(
      (selectedToolName) => `formattedResult-${selectedToolName}.json`
    );
    let results = [];

    for (let i = 0; i < fileNames.length; i++) {
      const toolResult = readJsonFileSync(
        `${process.cwd()}\\formattedResults\\${fileNames[i]}`
      );
      if (toolResult) {
        for (const result of toolResult) {
          let existingResult = true;

          const alreadyProcessedVulInTheSameFile = results.filter(
            (r) => r.vulPath === result.vulPath
          );

          const functionsInTheCurrentFile =
            this.metaData.find(
              (metaSlice) => metaSlice.vulPath === result.vulPath
            )?.functionsInVul ?? [];

          switch (this.analysisLevel) {
            case "file":
              existingResult = alreadyProcessedVulInTheSameFile.length > 0;
              break;

            case "function":
              existingResult = alreadyProcessedVulInTheSameFile.find(
                (v) =>
                  this.getFunctionNameWithLineNumer(
                    functionsInTheCurrentFile,
                    v.lineNumber
                  ) ===
                  this.getFunctionNameWithLineNumer(
                    functionsInTheCurrentFile,
                    result.lineNumber
                  )
              )
                ? true
                : false;
              break;

            case "line":
              existingResult = alreadyProcessedVulInTheSameFile.find(
                (v) => v.lineNumber === result.lineNumber
              )
                ? true
                : false;
              break;
          }

          if (!existingResult) {
            results.push(result);
          }
        }
      }
    }

    console.log(`***OR LOGIC*** - ${this.analysisLevel.toUpperCase()}`);
    this.setFoundAndNotFound(results);
    this.analyzer.evaluateResult(
      this.found,
      this.notFound,
      this.getTotalVulCount()
    );
  };

  withMajorityLogic = async () => {};
}
