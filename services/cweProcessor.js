import { findAllIndexes } from "./arryas.js";
import { readJsonFileSync } from "./file.js";

export const getCWEsCount = (dataSource) => {
  let data = dataSource;
  if (typeof dataSource === "string") data = readJsonFileSync(dataSource);

  const allCWEs = data.reduce((acc, r) => [...acc, ...r.CWEs], []);
  const allCWEsWithoutDuplicates = [...new Set(allCWEs)].sort((a, b) =>
    a.localeCompare(b)
  );

  const cweRecords = {};

  allCWEsWithoutDuplicates.forEach(
    (cwe) =>
      (cweRecords[cwe] = findAllIndexes(
        allCWEs,
        (value) => value === cwe
      ).length)
  );

  return cweRecords;
};

export const getDetectedCWEsPercentage = (
  totalCWEsRecord,
  detectedCWEsRecord
) => {
  const CWEsPercentage = {};

  for (const CWE in totalCWEsRecord) {
    CWEsPercentage[CWE] = detectedCWEsRecord[CWE] / totalCWEsRecord[CWE] || 0;
  }

  return CWEsPercentage;
};
