import { readJsonFileSync } from "./services/file.js";

export default class Analyzer {
  evaluateResult = (results) => {
    let tp = 0;
    let fp = 0;
    let fn = 0;

    const metaData = readJsonFileSync(
      `${process.cwd()}\\repositories\\ossf\\metaData.json`
    );

    const found = [];
    const notFound = [];

    for (const resultSlice of results) {
      if (
        metaData.find(
          (metaSlice) => metaSlice.vulPath === `/${resultSlice.vulPath}`
        )
      ) {
        found.push(resultSlice);
      } else {
        notFound.push(resultSlice);
      }
    }

    // found = Hits that are included in the known vul set
    // notFound = Hits that are not included in the known vul set

    tp = found.length;
    fp = notFound.length;
    fn = metaData.length - tp;

    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);
    const f1 = 2 * ((precision * recall) / (precision + recall));

    console.log("Total Vulnerabilities", metaData.length);
    console.log("Total Findings ", results.length);
    console.log("True Positive ", tp);
    console.log("False Positive ", fp);
    console.log("False Negative ", fn);
    console.log("Precision ", precision);
    console.log("Recall ", recall);
    console.log("F1 Score  ", f1);
  };
}
