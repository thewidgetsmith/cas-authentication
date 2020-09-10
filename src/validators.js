/* eslint-disable camelcase */
/* spell-checker:ignore attributestatement */
/* spell-checker:ignore attributevalue */
/* spell-checker:ignore authenticationfailure */
/* spell-checker:ignore authenticationsuccess */
/* spell-checker:ignore authenticationstatement */
/* spell-checker:ignore nameidentifier */
/* spell-checker:ignore samlp */
/* spell-checker:ignore serviceresponse */
/* spell-checker:ignore statuscode */

/**
 * CAS Ticket Validator Functions
 */
'use strict'

const debug = require('debug')('node-cas:validator')
const parseXML = require('xml2js').parseString
const XMLProcessors = require('xml2js/lib/processors')
const { CAS_PROTOCOL } = require('./constants')

const XML_PROCESSORS_CONFIG = {
  trim: true,
  normalize: true,
  explicitArray: false,
  tagNameProcessors: [XMLProcessors.normalize, XMLProcessors.stripPrefix]
}

/**
 * CAS 1.0 Protocol Ticket Validator
 *
 * @param {} body -
 * @param {} callback -
 */
const Cas10TicketValidator = function (body, callback) {
  debug('CAS10 validator ticket body', body)
  const lines = body.split('\n')
  if (lines[0] === 'yes' && lines.length >= 2) {
    callback(null, lines[1])
  } else if (lines[0] === 'no') {
    callback(new Error('CAS authentication failed.'))
  } else {
    callback(new Error('Invalid Response from CAS server.'))
  }
}

/**
 * CAS 2.0 Protocol Ticket Validator
 *
 * @param {} body -
 * @param {} callback -
 */
const Cas20TicketValidator = function (body, callback) {
  debug('CAS20 validator ticket body', body)
  parseXML(body, XML_PROCESSORS_CONFIG, (err, result) => {
    if (err) {
      callback(new Error('Response from CAS server was bad.'))
      return
    }

    try {
      const failure = result.serviceresponse.authenticationfailure
      if (failure) {
        callback(new Error('CAS authentication failed (' + failure.$.code + ').'))
        return
      }

      const success = result.serviceresponse.authenticationsuccess
      if (success) {
        callback(null, success.user, success.attributes)
      } else {
        callback(new Error('CAS authentication failed.'))
      }
    } catch (err) {
      debug('CAS20TicketValidator catch block', body, err)
      callback(new Error('CAS authentication failed.'))
    }
  })
}

/**
 * CAS 3.0 Protocol Ticket Validator
 *
 * @param {} body -
 * @param {} callback -
 */
const Cas30TicketValidator = function (body, callback) {
  debug('CAS30 validator ticket body', body)
  parseXML(body, XML_PROCESSORS_CONFIG, (err, result) => {
    if (err) {
      callback(new Error('Response from CAS server was bad.'))
      return
    }

    try {
      const failure = result.serviceresponse.authenticationfailure
      if (failure) {
        callback(new Error('CAS authentication failed (' + failure.$.code + ').'))
        return
      }

      const success = result.serviceresponse.authenticationsuccess
      if (success) {
        callback(null, success.user, success.attributes)
      } else {
        callback(new Error('CAS authentication failed.'))
      }
    } catch (err) {
      debug('CAS30TicketValidator catch block', body, err)
      callback(new Error('CAS authentication failed.'))
    }
  })
}

/**
 * SAML 1.1 Protocol Ticket Validator
 */
const Saml11TicketValidator = function (body, callback) {
  debug('SAML11 validator ticket body', body)
  parseXML(body, XML_PROCESSORS_CONFIG, (err, result) => {
    if (err) {
      debug()
      callback(new Error('Invalid response from CAS server.'))
      return
    }

    try {
      const samlResponse = result.envelope.body.response
      const success = samlResponse.status.statuscode.$.Value.split(':')[1]
      if (success !== 'Success') {
        callback(new Error('CAS authentication failed (' + success + ').'))
      } else {
        const attributes = {}
        let attributesArray = samlResponse.assertion.attributestatement.attribute

        if (!(attributesArray instanceof Array)) {
          attributesArray = [attributesArray]
        }
        attributesArray.forEach((attr) => {
          let thisAttrValue
          if (attr.attributevalue instanceof Array) {
            thisAttrValue = []
            attr.attributevalue.forEach((v) => {
              thisAttrValue.push(v._)
            })
          } else {
            thisAttrValue = attr.attributevalue._
          }
          attributes[attr.$.AttributeName] = thisAttrValue
        })
        callback(null, samlResponse.assertion.authenticationstatement.subject.nameidentifier, attributes)
      }
    } catch (err) {
      debug('SAML11TicketValidator catch block', body, err)
      callback(new Error('CAS authentication failed.'))
    }
  })
}

/**
 * @callback ValidatorCallback
 * @param {Error} error
 * @param {string} user
 * @param {Object} attributes
 */

/**
 * @typedef {function} TicketValidator
 * @param {string} body
 * @param {ValidatorCallback} callback
 */

/**
 * @typedef {Object} ValidatorResponse
 * @param {string} url
 * @param {TicketValidator} fn
 */

/**
 * Returns the appropriate validate URL and TicketValidator function given the CAS Protocol version.
 *
 * @param {string} casVersion
 * @returns {ValidatorResponse}
 */
exports.getCasValidatorParameters = function (casVersion) {
  switch (casVersion) {
    case CAS_PROTOCOL.CAS_1_0:
      return {
        url: '/validate',
        fn: Cas10TicketValidator
      }

    case CAS_PROTOCOL.CAS_2_0:
      return {
        url: '/serviceValidate',
        fn: Cas20TicketValidator
      }

    case CAS_PROTOCOL.CAS_3_0:
      return {
        url: '/p3/serviceValidate',
        fn: Cas30TicketValidator
      }

    case CAS_PROTOCOL.SAML_1_1:
      return {
        url: '/samlValidate',
        fn: Saml11TicketValidator
      }

    default:
      throw new Error(`CAS Protocol version '${casVersion}' is invalid. Refer to the documentation for allowed versions.`)
  }
}
