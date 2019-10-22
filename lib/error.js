'use strict';

class JWTError extends Error {
  constructor(_code, _message) {
    super(_message);

    this.code = _code;
  }
}

module.exports = JWTError;
