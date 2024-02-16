import { mergeJsonFiles } from "./services/file.js";
import readline from "readline";
import Secbench from "./repositories/secbench/secbench.js";
import Ossf from "./repositories/ossf/ossf.js";
import { sonarqube } from "./tools/sonarqube.js";
import { CodeQl } from "./tools/codeql.js";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const MENU_TEXT = `\nChoose from the following options.
1- Fetch Secbench-Part1 Commits
2- Fetch Secbench-Part2 Commits
3- Fetch Ossf Commits
4- Merge json files
5- End Program\n
`;

const getUserInput = async (question) => {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
};

const main = async () => {
  let shouldContinue = true;

  while (shouldContinue) {
    const option = await getUserInput(MENU_TEXT);
    switch (parseInt(option)) {
      case 1:
      case 2:
        await new Secbench().scrape(option);
        break;
      case 3:
        await new Ossf().scrape();
        break;
      case 4:
        const path = await getUserInput(
          "Enter folder path, containing json files: "
        );
        await mergeJsonFiles(path);
        break;
      case 5:
        shouldContinue = false;
        rl.close();
        break;
    }
  }
};

// main();

const sonarqubeObj = new sonarqube();
const issues2 = await sonarqubeObj.fetchResultsFromServer("VULNERABILITY");
// const issues1 = await sonarqubeObj.fetchResultsFromServer("BUG");
// const issues3 = await sonarqubeObj.fetchResultsFromServer("CODE_SMELL");

const codeql = new CodeQl();
await codeql.convertCsvToFormattedResult("./datasets/ossf_f - Copy/new.csv");

process.exit();
