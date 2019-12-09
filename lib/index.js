'use strict';

const extend = require('extend');
const jwt = require('jsonwebtoken');

const modelError = require('./error');
const modelCommon = require('./common');
const mergeRights = require('./mergeRights');

function factory(_config) {
  const proto = {};
  const config = Object.assign({
    keys: {}
  }, _config);

  function sign(_payload, _alias, _options) {
    const key = config.keys[_alias];
    if (!key) {
      throw new modelError('missingKey', `Unknown [${_alias}] key`);
    } else if (!key.privateKey) {
      throw new modelError('missingPrivate', `Missing private key for [${_alias}] key`);
    }

    const options = extend(true, {}, _options, {
      keyid: key.kid,
      algorithm: key.algorithm
    });

    return jwt.sign(_payload, key.privateKey, options);
  }

  function hasRight(_token, _right) {
    const parts = _right.toString().split(modelCommon.RIGHT_SEPARATOR);
    let pointer = _token.rights;
    for (const part of parts) {
      if (pointer === modelCommon.RIGHT_WILDCARD) {
        return true;
      } else if (!(part in pointer)) {
        return false;
      }

      pointer = pointer[part];
    }

    return true;
  }

  function checkRight(_token, _right) {
    if (!hasRight(_token, _right)) {
      throw new modelError('right', `Token doesn't hold the requested [${_right}] right`);
    }
  }

  function verify(_token, _scope, _options) {
    const data = jwt.decode(_token, {complete: true});
    if (!data) {
      throw new modelError('invalidToken', 'Invalid token');
    }

    const key = Object.values(config.keys).find(k => k.kid === data.header.kid && k.scopes.includes(_scope));
    if (!key) {
      throw new modelError('missingKey', 'No matching key found');
    }

    const options = extend(true, {}, _options, {
      algorithm: key.algorithm
    });

    try {
      const token = jwt.verify(_token, key.publicKey, options);

      Object.defineProperties(token, {
        hasRight: {value: _right => hasRight(token, _right)},
        checkRight: {value: _right => checkRight(token, _right)}
      });

      return token;
    } catch (ex) {
      throw new modelError('verify', 'Verification failed');
    }
  }

  Object.defineProperties(proto, {
    sign: {enumerable: true, value: sign},
    verify: {enumerable: true, value: verify},
    hasRight: {enumerable: true, value: hasRight},
    checkRight: {enumerable: true, value: checkRight}
  });

  return proto;
}

Object.defineProperties(factory, {
  JWTError: {enumerable: true, value: modelError},
  mergeRights: {enumerable: true, value: mergeRights}
});

module.exports = factory;
