export const getCWEsCount = (dataSource) => {
  let data = dataSource;
  if (typeof dataSource === "string") data = readJsonFileSync(dataSource);

  const allCWEs = data.reduce((acc, r) => [...acc, ...r.CWEs], []);
  const allCWEsWithoutDuplicates = [...new Set(allCWEs)];

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
    CWEsPercentage[CWE] = totalCWEsRecord[CWE] / detectedCWEsRecord[CWE] || 0;
    console.log(CWEsPercentage[CWE]);
  }

  return CWEsPercentage;
};
