import { nanoid } from "nanoid";
import Analyzer from "./analyzer.js";
import { readJsonFileSync, readDir } from "./services/file.js";

export default class Combiner {
  mode;
  analyzer;

  constructor() {
    this.mode = "individual";
    this.analyzer = new Analyzer();
  }

  evaluateIndividualTool = async (toolName, analysisLevel) => {
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

    this.analyzer.evaluateResult(toolResult);
  };

  withAndLogic = async (analysisLevel) => {
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
    this.analyzer.evaluateResult(results);
  };

  withOrLogic = async (analysisLevel) => {
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
    this.analyzer.evaluateResult([...results.values()]);
  };

  withMajorityLogic = async (analysisLevel) => {};
}
