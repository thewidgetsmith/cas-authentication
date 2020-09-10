/**
 *
 */
'use strict'

/**
 * The CAS authentication types.
 * @enum {number}
 */
exports.AUTH_TYPE = {
  BOUNCE: 0,
  BOUNCE_REDIRECT: 1,
  BLOCK: 2
}

/**
 * The CAS Protocol Versions
 * @enum { string}
 */
exports.CAS_PROTOCOL = {
  CAS_1_0: '1.0',
  CAS_2_0: '2.0',
  CAS_3_0: '3.0',
  SAML_1_1: 'saml1.1'
}
