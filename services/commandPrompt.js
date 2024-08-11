import readline from "readline";
import Secbench from "../repositories/secbench/secbench.js";
import Ossf from "../repositories/ossf/ossf.js";
import JavascriptDataset from "../repositories/javascriptDataset/javascriptDataset.js";
import Combiner from "../combiner.js";
import { Sonarqube } from "../tools/sonarqube.js";
import { CodeQl } from "../tools/codeql.js";
import { Snyk } from "../tools/snyk.js";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

export default class CommandPrompt {
  breadcrumbs = ["Main menu"];
  combiner = new Combiner();

  start = async () => {
    let shouldContinue = true;

    const getFullMenu = () => {
      return {
        ["Main menu"]: {
          title: "Main menu",
          options: `
1- Fetch options
2- Convert to formatted outputs
3- Combine formatted results
4- Back
5- End Program\n
`,
        },
        ["Fetch options"]: {
          title: "Fetch options",
          options: `
1- Fetch both Ossf and Javascript datasets
2- Fetch Ossf dataset
3- Fetch Javascript dataset
4- Fetch Secbench dataset Part1
5- Fetch Secbench dataset Part2
6- Back
7- End Program\n
`,
        },
        ["Convert to formatted outputs"]: {
          title: "Convert to formatted outputs",
          options: `
1- Convert all results
2- Convert ${process.env.TOOL1_NAME} results (server should be active)
3- Convert ${process.env.TOOL2_NAME} results
4- Convert ${process.env.TOOL3_NAME} results
5- Back
6- End Program\n
`,
        },
        ["Combine formatted results"]: {
          title: "Combine formatted results",
          options: `
1- Run all (activate disabled tools automatically)
2- By tool or logic (only process with currently active tools)
3- By granularity-level (only process with currently active tools)
4- Switch tool
5- Back
6- End Program\n
`,
        },
        ["By tool or logic"]: {
          title: "By tool or logic",
          options: `
1- ${process.env.TOOL1_NAME}
2- ${process.env.TOOL2_NAME}
3- ${process.env.TOOL3_NAME}
4- AND logic
5- OR logic
6- Back
7- End Program\n
`,
        },
        ["By granularity-level"]: {
          title: "By granularity-level",
          options: `
1- File level
2- Function level
3- Line level
4- Back
5- End Program\n
`,
        },
        ["Switch tool"]: {
          title: "Switch tool",
          options:
            "\n" +
            this.combiner.availableTools
              .map(
                (tool, index) =>
                  `${index + 1}- ${tool.name}: ${
                    tool.isActive ? "Enabled" : "Disabled"
                  }\n`
              )
              .join("") +
            "4- Back\n5- End Program\n",
        },
      };
    };

    const getUserInput = async (question) => {
      return new Promise((resolve) =>
        rl.question(question, (answer) => resolve(answer))
      );
    };

    const getCurrentMenu = (fullMenu) => {
      return fullMenu[this.breadcrumbs[this.breadcrumbs.length - 1]];
    };

    const goBack = () => {
      console.clear();
      if (this.breadcrumbs.length === 1) {
        console.log("\nCan not go back");
        return;
      }

      this.breadcrumbs.pop();
    };

    const end = () => {
      shouldContinue = false;
      rl.close();
    };

    const printBreadcrumbs = () => {
      console.log(`\n${this.breadcrumbs.join(" --> ")}`);
    };

    while (shouldContinue) {
      const fullMenu = getFullMenu();
      const currentMenu = getCurrentMenu(fullMenu);
      printBreadcrumbs();
      const optionIndex = await getUserInput(currentMenu.options);
      switch (currentMenu.title) {
        case "Main menu":
          switch (optionIndex) {
            case "1":
              console.clear();
              this.breadcrumbs.push("Fetch options");
              break;
            case "2":
              console.clear();
              this.breadcrumbs.push("Convert to formatted outputs");
              break;
            case "3":
              console.clear();
              this.breadcrumbs.push("Combine formatted results");
              break;
            case "4":
              goBack();
              break;
            case "5":
              end();
              break;
          }
          break;
        case "Fetch options":
          switch (optionIndex) {
            case "1":
              await new Ossf().scrape();
              await new JavascriptDataset().scrape(false);
              break;
            case "2":
              await new Ossf().scrape();
              break;
            case "3":
              await new JavascriptDataset().scrape(false);
              break;
            case "4":
              await new Secbench().scrape(1);
              break;
            case "5":
              await new Secbench().scrape(2);
              break;
            case "6":
              goBack();
              break;
            case "7":
              end();
              break;
          }
          break;
        case "Convert to formatted outputs":
          switch (optionIndex) {
            case "1":
              console.clear();
              console.log(
                "Converted sonarqube, codeql and snyk results to their respective formatted output"
              );
              await new Sonarqube().convertTypeToFormattedResult(
                "VULNERABILITY"
              );
              await new CodeQl().convertCsvToFormattedResult();
              await new Snyk().convertJsonToFormattedResult();
              break;
            case "2":
              console.clear();
              console.log("Converted sonarqube results to formatted output");
              await new Sonarqube().convertTypeToFormattedResult(
                "VULNERABILITY"
              );
              break;
            case "3":
              console.clear();
              console.log("Converted codeql results to formatted output");
              await new CodeQl().convertCsvToFormattedResult();
              break;
            case "4":
              console.clear();
              console.log("Converted snyk results to formatted output");
              await new Snyk().convertJsonToFormattedResult();
              break;
            case "5":
              goBack();
              break;
            case "6":
              end();
              break;
          }
          break;
        case "Combine formatted results":
          switch (optionIndex) {
            case "1":
              this.combiner.activateAllTools();

              this.combiner.analyzeOnFileLevel();
              this.combiner.runAllCombinations();

              this.combiner.analyzeOnFunctionLevel();
              this.combiner.runAllCombinations();

              this.combiner.analyzeOnLineLevel();
              this.combiner.runAllCombinations();
              break;
            case "2":
              console.clear();
              this.breadcrumbs.push("By tool or logic");
              break;
            case "3":
              console.clear();
              this.breadcrumbs.push("By granularity-level");
              break;
            case "4":
              console.clear();
              this.breadcrumbs.push("Switch tool");
              break;
            case "5":
              goBack();
              break;
            case "6":
              end();
              break;
          }
          break;
        case "By tool or logic":
          switch (optionIndex) {
            case "1":
              this.combiner.runCombinerByTool(process.env.TOOL1_NAME);
              break;
            case "2":
              this.combiner.runCombinerByTool(process.env.TOOL2_NAME);
              break;
            case "3":
              this.combiner.runCombinerByTool(process.env.TOOL3_NAME);
              break;
            case "4":
              this.combiner.runCombinerByLogic(() =>
                this.combiner.withAndLogic()
              );
              break;
            case "5":
              this.combiner.runCombinerByLogic(() =>
                this.combiner.withOrLogic()
              );
              break;
            case "6":
              goBack();
              break;
            case "7":
              end();
              break;
          }
          break;
        case "By granularity-level":
          switch (optionIndex) {
            case "1":
              this.combiner.analyzeOnFileLevel();
              this.combiner.runCombinerByGranularityLevel();
              break;
            case "2":
              this.combiner.analyzeOnFunctionLevel();
              this.combiner.runCombinerByGranularityLevel();
              break;
            case "3":
              this.combiner.analyzeOnLineLevel();
              this.combiner.runCombinerByGranularityLevel();
              break;
            case "4":
              goBack();
              break;
            case "5":
              end();
              break;
          }
          break;
        case "Switch tool":
          switch (optionIndex) {
            case "1":
              console.clear();
              this.combiner.switchTool(process.env.TOOL1_NAME);
              break;
            case "2":
              console.clear();
              this.combiner.switchTool(process.env.TOOL2_NAME);
              break;
            case "3":
              console.clear();
              this.combiner.switchTool(process.env.TOOL3_NAME);
              break;
            case "4":
              goBack();
              break;
            case "5":
              end();
              break;
          }
          break;
      }
    }
  };
}
