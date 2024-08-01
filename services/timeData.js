export const getTimeStamp = () => {
  const date = new Date();
  return `${date.toDateString()} - ${date.getHours()}hh ${date.getMinutes()}mm ${date.getSeconds()}ss`;
};
