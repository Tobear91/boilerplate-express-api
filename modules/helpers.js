function checkBody(body, fields) {
  if (Object.values(body).length !== fields.length) return false;
  return !fields.some((field) => !body[field] || Object.hasOwn(body, field) === false);
}

module.exports = { checkBody };
