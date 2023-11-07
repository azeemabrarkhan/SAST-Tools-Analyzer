import { fetchCommit, fetchFile } from "./services/http.js";
import { makeDir, writeFileAsync, csvToArray } from "./services/file.js";
import { log, clearLog } from "./services/logger.js";
import readline from "readline";

const currentDir = process.cwd();
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});
const secbenchFilePath = `${currentDir}\\commitIDs\\secbench.csv`;

let vulnerablityCount = 1;
let fileNumber = 1;

const processCommit = async (baseUrl, vulPath, fixPath, shaV, sha) => {
  const commitUrl = `${baseUrl}/commits/${sha}`;
  makeDir(vulPath);
  makeDir(fixPath);

  return new Promise(async (resolve) => {
    try {
      const commitResponse = await fetchCommit(commitUrl);
      const commitData = await commitResponse.json();

      if (commitData.files && commitData.files.length > 0) {
        const fileNames = commitData.files.map((file) => file.filename);

        for (const fileName of fileNames) {
          console.log(`${fileNumber} - ${fileName}`);
          fileNumber++;
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
                `ERROR, while fetching file '${fileName}' from the url: ${vulFileUrl} - error trace: ${err}`
              );
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
                `ERROR, while fetching file '${fileName}' from the url: ${fixFileUrl} - error trace: ${err}`
              );
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
        `ERROR, while fetching commit from the url: ${commitUrl} - error trace: ${err}`
      );
    }
  });
};

const printMenu = async () => {
  return new Promise((resolve) => {
    rl.question(
      `\nChoose from the following option.
    1- Fetch Secbench Commits
    2- End Program\n
    `,
      (option) => resolve(parseInt(option))
    );
  });
};

const scrapSecbench = async () => {
  const secbenchData = await csvToArray(secbenchFilePath);
  for (const secbenchCommit of secbenchData) {
    const baseUrl = `https://api.github.com/repos/${secbenchCommit.owner}/${secbenchCommit.project}`;

    const vulPath = `${currentDir}\\datasets\\secbench\\vul\\${secbenchCommit.language}\\${secbenchCommit["cwe_id"]}\\${secbenchCommit.owner}\\${secbenchCommit.project}\\${vulnerablityCount}\\${secbenchCommit["sha-p"]}`;
    const fixPath = `${currentDir}\\datasets\\secbench\\fix\\${secbenchCommit.language}\\${secbenchCommit["cwe_id"]}\\${secbenchCommit.owner}\\${secbenchCommit.project}\\${vulnerablityCount}\\${secbenchCommit.sha}`;

    vulnerablityCount++;

    await processCommit(
      baseUrl,
      vulPath,
      fixPath,
      secbenchCommit["sha-p"],
      secbenchCommit.sha
    );
  }
};

const main = async () => {
  let shouldContinue = true;

  while (shouldContinue) {
    const option = await printMenu();
    switch (option) {
      case 1:
        await scrapSecbench();
        break;
      case 2:
        shouldContinue = false;
        rl.close();
        break;
    }
  }
};

clearLog();
main();
