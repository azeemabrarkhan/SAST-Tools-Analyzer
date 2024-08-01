export const findAllIndexes = (array, func) => {
  const results = [];
  for (let i = 0; i < array.length; i++) {
    if (func(array[i])) results.push(i);
  }
  return results;
};
