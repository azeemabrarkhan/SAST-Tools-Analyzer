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
