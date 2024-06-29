export default class Analyzer {
  evaluateResult = (
    found,
    notFound,
    notRecognizedPatches,
    totalVulnerabilities
  ) => {
    // found = Hits that are included in the known vul set
    // notFound = Hits that are not included in the known vul set

    const tp = found;
    const fp = notFound;
    const fn = totalVulnerabilities - tp;

    const precision = tp / (tp + fp);
    const recall = tp / (tp + fn);
    const f1 = 2 * ((precision * recall) / (precision + recall));

    console.log("Total Vulnerabilities", totalVulnerabilities);
    console.log("Total Findings ", tp + fp);
    console.log("True Positive ", tp);
    console.log("False Positive ", fp);
    console.log("False Negative ", fn);
    console.log("Not recognized patches ", notRecognizedPatches);
    console.log("Precision ", precision);
    console.log("Recall ", recall);
    console.log("F1 Score  ", f1);
    console.log("");
  };
}
