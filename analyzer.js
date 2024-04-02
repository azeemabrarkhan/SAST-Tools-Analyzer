import { readJsonFileSync } from "./services/file.js";

export default class Analyzer {
  evaluateResult = (found, notFound) => {
    const metaData = readJsonFileSync(
      `${process.cwd()}\\repositories\\ossf\\metaData.json`
    );

    // found = Hits that are included in the known vul set
    // notFound = Hits that are not included in the known vul set

    const tp = found.length;
    const fp = notFound.length;
    const fn = metaData.length - tp;

    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);
    const f1 = 2 * ((precision * recall) / (precision + recall));

    console.log("Total Vulnerabilities", metaData.length);
    console.log("Total Findings ", tp + fp);
    console.log("True Positive ", tp);
    console.log("False Positive ", fp);
    console.log("False Negative ", fn);
    console.log("Precision ", precision);
    console.log("Recall ", recall);
    console.log("F1 Score  ", f1);
  };
}
