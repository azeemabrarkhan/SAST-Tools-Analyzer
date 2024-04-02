import { nanoid } from "nanoid";
import Analyzer from "./analyzer.js";
import { readJsonFileSync, readDir } from "./services/file.js";

export default class Combiner {
  found;
  notFound;
  metaData;
  analyzer;
  analysisLevel;

  constructor() {
    this.found = [];
    this.notFound = [];
    this.metaData = readJsonFileSync(
      `${process.cwd()}\\repositories\\ossf\\metaData.json`
    );
    this.analyzer = new Analyzer();
    this.analysisLevel = "file";
  }

  analyzeOnFileLevel = () => {
    this.analysisLevel = "file";
  };

  analyzeOnFunctionLevel = () => {
    this.analysisLevel = "function";
  };

  analyzeOnLineLevel = () => {
    this.analysisLevel = "line";
  };

  setFoundAndNotFound = (results) => {
    this.found = [];
    this.notFound = [];

    for (const resultSlice of results) {
      if (
        this.metaData.find(
          (metaSlice) => metaSlice.vulPath === `/${resultSlice.vulPath}`
        )
      ) {
        this.found.push(resultSlice);
      } else {
        this.notFound.push(resultSlice);
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
        console.log("***CODE-QL***");
        break;

      case "sonarqube":
        toolResult = readJsonFileSync(
          `${process.cwd()}\\formattedResults\\formattedResult-sonarqube.json`
        );
        console.log("***SONAR QUBE***");
        break;
    }

    this.setFoundAndNotFound(toolResult);
    this.analyzer.evaluateResult(this.found, this.notFound);
  };

  withAndLogic = async () => {
    const fileNames = await readDir(`${process.cwd()}\\formattedResults`);
    let toolResults = new Map();
    const results = [];

    for (let i = 0; i < fileNames.length; i++) {
      const toolResult = readJsonFileSync(
        `${process.cwd()}\\formattedResults\\${fileNames[i]}`
      );
      if (toolResult) toolResults.set(i, toolResult);
    }

    for (const vul of toolResults.get(0)) {
      let isVulnerable = true;

      for (let i = 1; i < toolResults.size && isVulnerable; i++) {
        const toolResult = toolResults.get(i);
        isVulnerable = toolResult.find(
          (result) => result.vulPath === vul.vulPath
        )
          ? true
          : false;
      }
      if (isVulnerable) {
        results.push(vul);
      }
    }

    console.log("***AND LOGIC***");
    this.setFoundAndNotFound(results);
    this.analyzer.evaluateResult(this.found, this.notFound);
  };

  withOrLogic = async () => {
    const fileNames = await readDir(`${process.cwd()}\\formattedResults`);
    let results = new Map();

    for (let i = 0; i < fileNames.length; i++) {
      const toolResult = readJsonFileSync(
        `${process.cwd()}\\formattedResults\\${fileNames[i]}`
      );
      if (toolResult) {
        for (const result of toolResult) {
          const existingResult = results.get(result.vulPath);
          if (!existingResult) {
            results.set(result.vulPath, result);
          }
        }
      }
    }

    console.log("***OR LOGIC***");
    this.setFoundAndNotFound([...results.values()]);
    this.analyzer.evaluateResult(this.found, this.notFound);
  };

  withMajorityLogic = async () => {};
}
