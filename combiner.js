import Analyzer from "./analyzer.js";
import { readJsonFileSync } from "./services/file.js";

export default class Combiner {
  mode;
  analyzer;

  constructor() {
    this.mode = "individual";
    this.analyzer = new Analyzer();
  }

  createFormattedResult = async (toolName) => {
    let toolResult;

    switch (toolName) {
      case "codeql":
        toolResult = readJsonFileSync(
          `${process.cwd()}\\formattedResults\\formattedResult-codeql.json`
        );
        for (const vul of toolResult) vul.isVulnerable = true;
        break;

      case "sonarqube":
        toolResult = readJsonFileSync(
          `${process.cwd()}\\formattedResults\\formattedResult-sonarqube.json`
        );
        for (const vul of toolResult) vul.isVulnerable = true;
        break;
    }

    this.analyzer.evaluateResult(toolResult);
  };
}
