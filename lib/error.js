'use strict';

class JWTError extends Error {
  constructor(_message) {
    super(_message);
  }
}

module.exports = JWTError;
