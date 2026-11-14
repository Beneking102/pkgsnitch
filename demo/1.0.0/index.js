'use strict';

module.exports = function leftPad(value, length, fill = ' ') {
  return String(value).padStart(length, fill);
};
