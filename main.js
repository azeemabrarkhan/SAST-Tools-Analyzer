import { mergeJsonFiles, readJsonFileSync } from "./services/file.js";
import readline from "readline";
import Secbench from "./repositories/secbench/secbench.js";
import Ossf from "./repositories/ossf/ossf.js";
import { sonarqube } from "./tools/sonarqube.js";
import { CodeQl } from "./tools/codeql.js";
import Combiner from "./combiner.js";
import { Snyk } from "./tools/snyk.js";
import fs from "fs";
import AbstractSynTree from "./services/abstractSynTree.js";
import esTree from "@typescript-eslint/typescript-estree";
import { printRecursiveObject } from "./services/print.js";
import { fetchFile } from "./services/http.js";
import JavascriptDataset from "./repositories/javascriptDataset/javascriptDataset.js";
import GenerativeAI from "./services/generativeAI.js";
import { getLinesFromString } from "./utils/text.js";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const MENU_TEXT = `\nChoose from the following options.
1- Fetch Secbench dataset Part1
2- Fetch Secbench dataset Part2
3- Fetch Ossf dataset
4- Fetch Javascript dataset with generative AI
5- Fetch Javascript dataset w/o generative AI
6- Fetch both Ossf and Javascript datasets w/o generative AI
7- Merge json files
8- End Program\n
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
        await new JavascriptDataset().scrape(true);
        break;
      case 5:
        await new JavascriptDataset().scrape(false);
        break;
      case 6:
        await new Ossf().scrape();
        await new JavascriptDataset().scrape(false);
        break;
      case 7:
        const path = await getUserInput(
          "Enter folder path, containing json files: "
        );
        await mergeJsonFiles(path);
        break;
      case 8:
        shouldContinue = false;
        rl.close();
        break;
    }
  }
};

await main();

// const javascriptDataset = new JavascriptDataset();
// await javascriptDataset.scrape(true);

async function test() {
  const meta = readJsonFileSync(
    `${process.cwd()}\\repositories\\javascriptDataset\\metaData.json`
  );

  const initialAIPrompt = `Code snipets are needed to be analyzed for vulnerability detection. Snipets will be supplied continously. They are needed
  to be checked for vulnererabilities. Do not provide long answers for every input, instead just provide a detailed summary in the end regarding 
  the types of vulnerabilities or issues found in the code snipets. Please also include CVE and CWE, if possible.`;

  const generativeAI = new GenerativeAI();

  console.log("Initial prompt to the AI: ", initialAIPrompt);
  const initialResponseFromTheAI = await generativeAI.chatWithAI(
    initialAIPrompt
  );
  console.log("\nInitial response from the AI: ", initialResponseFromTheAI);

  const responses = [];
  for await (const record of [meta[0], meta[1], meta[2]]) {
    const text = fs.readFileSync(
      `${record.dirPath}\\${record.fileName}`,
      "utf-8"
    );

    for await (const func of record.innerMostVulnerableFunctions) {
      const response = generativeAI.chatWithAI(
        getLinesFromString(text, func.startLine, func.endLine)
      );
      responses.push(response);
      console.log(response);
    }
  }

  await Promise.all(responses);
  const finalAIPrompt = `All of the code snippets have been provided, now please provide the required summary. 
  Please also mention the total number of snipets provided, the vulnerable and the clean snipets.`;

  console.log("\nFinal prompt to the AI: ", finalAIPrompt);
  const finalResponseFromTheAI = await generativeAI.chatWithAI(finalAIPrompt);
  console.log("\nFinal response from the AI: ", finalResponseFromTheAI);
  console.log("\n" + responses.length);
  console.log("****************************");
  console.log(responses[0]);
  console.log("****************************");
  console.log(responses[1]);
  console.log("****************************");
  console.log(responses[2]);
  console.log("****************************");
  console.log(responses[3]);
  console.log("****************************");

  const history = await generativeAI.chatObject.getHistory();
  history.forEach((a) => {
    printRecursiveObject(a);
  });
}

const aiQuestions = [
  "What are the main differences between narrow AI and general AI?",
  "How does machine learning differ from traditional programming?",
  "Can you explain the concept of neural networks?",
  "What are some real-world applications of deep learning?",
  "How does natural language processing (NLP) work?",
  "What is the role of AI in healthcare?",
  "How is AI transforming the field of finance?",
  "What are the ethical considerations of using AI in decision-making?",
  "How does reinforcement learning differ from supervised learning?",
  "What are the benefits and challenges of autonomous vehicles?",
  "Can you explain the Turing Test and its significance in AI?",
  "How is AI used in the field of robotics?",
  "What are some examples of AI in everyday consumer products?",
  "How does computer vision work in AI systems?",
  "What is the importance of data in training AI models?",
  "How do recommendation systems work on platforms like Netflix and Amazon?",
  "What is the impact of AI on the job market?",
  "How is AI being used in climate change research?",
  "Can you explain the concept of a generative adversarial network (GAN)?",
  "What are some key challenges in developing AI for natural language understanding?",
  "How does AI enhance cybersecurity measures?",
  "What are the potential risks of AI in autonomous weapons?",
  "How is AI used in the field of education?",
  "Can AI be creative? Provide examples.",
  "How does AI contribute to smart city development?",
  "What is the significance of explainable AI (XAI)?",
  "How is AI changing the landscape of e-commerce?",
  "What are some applications of AI in agriculture?",
  "Can you discuss the future of AI in space exploration?",
  "How do chatbots and virtual assistants work?",
  "What is the role of AI in personalized medicine?",
  "How does AI help in fraud detection?",
  "What are the implications of AI in social media?",
  "Can AI predict human behavior? How accurate is it?",
  "How is AI used in game development?",
  "What are some advancements in AI-powered language translation?",
  "How does AI impact legal systems and law enforcement?",
  "What are the privacy concerns associated with AI?",
  "How is AI used in supply chain management?",
  "Can AI improve mental health treatments? How?",
  "What are the limitations of current AI technologies?",
  "How does AI handle big data analysis?",
  "What are some success stories of AI in customer service?",
  "How is AI contributing to advancements in renewable energy?",
  "What is the role of AI in predictive maintenance?",
  "How does AI facilitate remote work and collaboration?",
  "What are some challenges in integrating AI into existing systems?",
  "How can AI help in disaster response and management?",
  "What are the trends in AI research and development?",
  "How does AI influence marketing and advertising strategies?",
];

// const generativeAI = new GenerativeAI();
// const responses = await generativeAI.getSeriesOfResponses({}, aiQuestions);
// console.log(responses.aiResponses);

// const response = await fetchFile(
//   "https://api.github.com/repos/jquery/jquery/contents/src/ajax.js?ref=c27dc018e22260b6ad084dff4505172e6b107178"
// );

// console.log(response);

// const file = fs.readFileSync("./test.js");
// try {
//   const funcs = new AbstractSynTree().getFunctionsLocations(file);
//   console.log(funcs);
//   //   // const funcs = esTree.parse(file, { loc: true });
//   //   // console.log(funcs.body);
//   //   // printRecursiveObject(funcs);
// } catch (err) {
//   console.log(err);
// }

// const sonarqubeObj = new sonarqube();
// const issues2 = await sonarqubeObj.fetchResultsFromServer("VULNERABILITY");
// const issues1 = await sonarqubeObj.fetchResultsFromServer("BUG");
// const issues3 = await sonarqubeObj.fetchResultsFromServer("CODE_SMELL");

// const codeql = new CodeQl();
// await codeql.convertCsvToFormattedResult("./datasets/ossf_f - Copy/new.csv");

// const snyk = new Snyk();
// await snyk.convertJsonToFormattedResult("./datasets/ossf_f - Copy/snyk.json");

// const combiner = new Combiner();

// const runCombiner = async () => {
//   await combiner.evaluateIndividualTool("codeql");
//   await combiner.evaluateIndividualTool("snyk");
//   await combiner.evaluateIndividualTool("sonarqube");
//   await combiner.withAndLogic();
//   await combiner.withOrLogic();
// };

// await runCombiner();

// combiner.analyzeOnFunctionLevel();
// await runCombiner();

// combiner.analyzeOnLineLevel();
// await runCombiner();

// combiner.deselectTool("sonarqube");

// await combiner.withAndLogic();

// combiner.analyzeOnFunctionLevel();
// await combiner.withAndLogic();

// combiner.analyzeOnLineLevel();
// await combiner.withAndLogic();

process.exit();
