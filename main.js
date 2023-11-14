import { fetchCommit, fetchFile } from "./services/http.js";
import {
  makeDir,
  writeFileAsync,
  csvToArray,
  mergeJsonFiles,
  readJsonFileSync,
} from "./services/file.js";
import { log, createNewLogFile } from "./services/logger.js";
import readline from "readline";

const currentDir = process.cwd();
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

let vulnerablityCount = 0;
let fileNumber = 0;

const processSecbenchCommit = async (baseUrl, vulPath, fixPath, shaV, sha) => {
  const commitUrl = `${baseUrl}/commits/${sha}`;
  makeDir(vulPath);
  makeDir(fixPath);

  return new Promise(async (resolve) => {
    try {
      const commitResponse = await fetchCommit(commitUrl);
      const commitData = await commitResponse.json();

      if (commitData.files && commitData.files.length > 0) {
        const fileNames = commitData.files
          .filter((file) => file.status !== "added")
          .map((file) => file.filename);

        for (const fileName of fileNames) {
          fileNumber++;
          console.log(`${fileNumber} - ${fileName}`);
          const splitFileName = fileName.split("/");
          const vulFileUrl = `${baseUrl}/contents/${fileName}?ref=${shaV}`;
          const fixFileUrl = `${baseUrl}/contents/${fileName}?ref=${sha}`;

          fetchFile(vulFileUrl)
            .then((text) =>
              writeFileAsync(
                `${vulPath}\\${splitFileName[splitFileName.length - 1]}`,
                text
              )
            )
            .catch((err) => {
              log(
                `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
              );
              resolve();
            });

          fetchFile(fixFileUrl)
            .then((text) => {
              writeFileAsync(
                `${fixPath}\\${splitFileName[splitFileName.length - 1]}`,
                text
              );
              if (fileNames.indexOf(fileName) === fileNames.length - 1) {
                resolve();
              }
            })
            .catch((err) => {
              log(
                `ERROR, while fetching post-fix file from the url: ${fixFileUrl} - error trace: ${err}`
              );
              resolve();
            });
        }
      } else if (commitData.files && commitData.files.length === 0) {
        log(
          `WARNING, files array does not contain any file for url: ${commitUrl} - message: ${commitData.message}`
        );
        resolve();
      } else {
        log(
          `WARNING, files array does not exist for url: ${commitUrl} - message: ${commitData.message}`
        );
        resolve();
      }
    } catch (err) {
      log(
        `ERROR, while fetching commit from the url: ${commitUrl} - message: ${commitData.message} - error trace: ${err}`
      );
      resolve();
    }
  });
};

const processOssfCommit = async (
  baseUrl,
  vulPath,
  fixPath,
  shaV,
  sha,
  fileName
) => {
  makeDir(vulPath);
  makeDir(fixPath);

  fileNumber++;
  console.log(`${fileNumber} - ${fileName}`);
  const splitFileName = fileName.split("/");
  const vulFileUrl = `${baseUrl}/contents/${fileName}?ref=${shaV}`;
  const fixFileUrl = `${baseUrl}/contents/${fileName}?ref=${sha}`;

  return fetchFile(vulFileUrl)
    .then((text) =>
      writeFileAsync(
        `${vulPath}\\${splitFileName[splitFileName.length - 1]}`,
        text
      )
    )
    .catch((err) =>
      log(
        `ERROR, while fetching pre-fix file from the url: ${vulFileUrl} - error trace: ${err}`
      )
    )
    .then(() =>
      fetchFile(fixFileUrl)
        .then((text) =>
          writeFileAsync(
            `${fixPath}\\${splitFileName[splitFileName.length - 1]}`,
            text
          )
        )
        .catch((err) =>
          log(
            `ERROR, while fetching post-fix file from the url: ${fixFileUrl} - error trace: ${err}`
          )
        )
    );
};

const getUserInput = async (question) => {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
};

const scrapeSecbench = async (partNumber) => {
  const secbenchData = await csvToArray(
    `${currentDir}\\commitIDs\\secbench${partNumber}.csv`
  );
  for (const secbenchCommit of secbenchData) {
    vulnerablityCount++;

    const baseUrl = `https://api.github.com/repos/${secbenchCommit.owner}/${secbenchCommit.project}`;

    const vulPath = `${currentDir}\\datasets\\secbench\\vul\\${secbenchCommit.language}\\${secbenchCommit["cwe_id"]}\\${secbenchCommit.owner}\\${secbenchCommit.project}\\${vulnerablityCount}\\${secbenchCommit["sha-p"]}`;
    const fixPath = `${currentDir}\\datasets\\secbench\\fix\\${secbenchCommit.language}\\${secbenchCommit["cwe_id"]}\\${secbenchCommit.owner}\\${secbenchCommit.project}\\${vulnerablityCount}\\${secbenchCommit.sha}`;

    await processSecbenchCommit(
      baseUrl,
      vulPath,
      fixPath,
      secbenchCommit["sha-p"],
      secbenchCommit.sha
    );
  }
};

const scrapeOssf = async () => {
  const ossfData = readJsonFileSync("commitIDs\\ossf.json");
  let numOfWeaknesses = 0;

  for (const ossfCommit of ossfData) {
    vulnerablityCount++;
    numOfWeaknesses += ossfCommit.prePatch.weaknesses.length;

    const splittedUrl = ossfCommit.repository.split("/");
    const ownerAndProject = `${splittedUrl[3]}/${splittedUrl[4].split(".")[0]}`;
    const baseUrl = `https://api.github.com/repos/${ownerAndProject}`;

    const vulPath = `${currentDir}\\datasets\\ossf\\vul\\${
      ossfCommit.CVE
    }\\${ownerAndProject.replace("/", "\\")}\\${vulnerablityCount}\\${
      ossfCommit.prePatch.commit
    }`;
    const fixPath = `${currentDir}\\datasets\\ossf\\fix\\${
      ossfCommit.CVE
    }\\${ownerAndProject.replace("/", "\\")}\\${vulnerablityCount}\\${
      ossfCommit.postPatch.commit
    }`;

    await processOssfCommit(
      baseUrl,
      vulPath,
      fixPath,
      ossfCommit.prePatch.commit,
      ossfCommit.postPatch.commit,
      ossfCommit.prePatch.weaknesses[0].location.file
    );
  }
};

const main = async () => {
  let shouldContinue = true;

  while (shouldContinue) {
    const option = await getUserInput(MENU_TEXT);
    switch (parseInt(option)) {
      case 1:
      case 2:
        await scrapeSecbench(option);
        break;
      case 3:
        await scrapeOssf();
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

createNewLogFile();
main();
