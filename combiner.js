import Analyzer from "./analyzer.js";
import { readJsonFileSync, readDir } from "./services/file.js";

export default class Combiner {
  mode;
  analyzer;

  constructor() {
    this.mode = "individual";
    this.analyzer = new Analyzer();
  }

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

    for (const vul of toolResult) vul.isVulnerable = true;
    this.analyzer.evaluateResult(toolResult);
  };

  withAndLogic = async () => {
    const fileNames = await readDir(`${process.cwd()}\\formattedResults`);
    let toolResults = new Map();

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
        );
      }

      vul.isVulnerable = isVulnerable ? true : false;
    }

    console.log("***AND LOGIC***");
    this.analyzer.evaluateResult(toolResults.get(0));
  };

  withOrLogic = async () => {
    const fileNames = await readDir(`${process.cwd()}\\formattedResults`);
    let results = [];

    for (let i = 0; i < fileNames.length; i++) {
      const toolResult = readJsonFileSync(
        `${process.cwd()}\\formattedResults\\${fileNames[i]}`
      );
      if (toolResult) results = [...results, ...toolResult];
    }

    for (const vul of results) vul.isVulnerable = true;

    console.log("***OR LOGIC***");
    // this.analyzer.evaluateResult(results);
  };

  withMajorityLogic = async () => {};
}
