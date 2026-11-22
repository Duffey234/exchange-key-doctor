'use strict';
module.exports = {
  ...require('./src/scan'),
  ...require('./src/check'),
  ...require('./src/explain'),
  RULES: require('./src/rules').RULES,
};
