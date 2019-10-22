'use strict';

const modelCommon = require('./common');

function mergeRights(_base, ..._extensions) {
  if (_base === modelCommon.RIGHT_WILDCARD) {
    return modelCommon.RIGHT_WILDCARD;
  }

  const base = _base || {};
  for (const extension of _extensions) {
    if (extension === modelCommon.RIGHT_WILDCARD) {
      return modelCommon.RIGHT_WILDCARD;
    }

    for (const [key, child] of Object.entries(extension || {})) {
      base[key] = mergeRights(base[key] || {}, child);
    }
  }

  return base;
}

module.exports = mergeRights;
