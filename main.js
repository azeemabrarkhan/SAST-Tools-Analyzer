import { mergeJsonFiles } from "./services/file.js";
import readline from "readline";
import Secbench from "./repositories/secbench/secbench.js";
import Ossf from "./repositories/ossf/ossf.js";
import AbstractSyntaxTree from "abstract-syntax-tree";
import fs from "fs";

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

main();

const source = "const answer = 42";
// const tree = new AbstractSyntaxTree(
//   fs.readFileSync(
//     `datasets\\ossf_f - Copy\\vul\\CVE-2016-10735\\twbs\\bootstrap\\2\\ba6a6f13691000ffaf22ef8e731513737659447f\\util.js`,
//     "utf-8"
//   )
// );
const tree = new AbstractSyntaxTree(`const add = async () => {
  const a = await 1;
  const b = 2;
  const c = a + b;
  return c;
}`);
// printRecursiveObject(tree.find("FunctionDeclaration").length); // [ { type: 'Literal', value: 42 } ]
// printRecursiveObject(tree.find("FunctionExpression")[0]); // [ { type: 'Literal', value: 42 } ]
// printRecursiveObject(tree.find("ArrowFunctionExpression")[1]); // [ { type: 'Literal', value: 42 } ]
printRecursiveObject(tree.find("AwaitExpression")[0]); // [ { type: 'Literal', value: 42 } ]

function printRecursiveObject(obj, indent = 0) {
  const spaces = " ".repeat(indent * 2);

  for (const key in obj) {
    if (typeof obj[key] === "object" && obj[key] !== null) {
      console.log(`${spaces}${key}: {`);
      printRecursiveObject(obj[key], indent + 1);
      console.log(`${spaces}},`);
    } else {
      console.log(`${spaces}${key}: "${obj[key]}",`);
    }
  }
}
