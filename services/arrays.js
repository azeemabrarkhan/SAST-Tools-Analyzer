export const findAllIndexes = (array, func) => {
  const results = [];
  for (let i = 0; i < array.length; i++) {
    if (func(array[i])) results.push(i);
  }
  return results;
};

export const sortArrayOfObjects = (array, parameterToSort, sortOrder) => {
  return array.sort((a, b) => {
    if (
      a[parameterToSort] === sortOrder[0] &&
      b[parameterToSort] !== sortOrder[0]
    ) {
      return -1;
    }
    if (
      a[parameterToSort] !== sortOrder[0] &&
      b[parameterToSort] === sortOrder[0]
    ) {
      return 1;
    }
    if (
      a[parameterToSort] === sortOrder[1] &&
      b[parameterToSort] !== sortOrder[1]
    ) {
      return -1;
    }
    if (
      a[parameterToSort] !== sortOrder[1] &&
      b[parameterToSort] === sortOrder[1]
    ) {
      return 1;
    }
    return 0;
  });
};
