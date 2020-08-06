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
 * CAS Authentication Client for Node.js
 */
'use strict'

const URL = require('url')
const http = require('http')
const https = require('https')
const parseXML = require('xml2js').parseString
const XMLProcessors = require('xml2js/lib/processors')

/**
 * The CAS authentication types.
 * @enum {number}
 */
const AUTH_TYPE = {
  BOUNCE: 0,
  BOUNCE_REDIRECT: 1,
  BLOCK: 2
}

/**
 *
 */
const XML_PROCESSORS_CONFIG = {
  trim: true,
  normalize: true,
  explicitArray: false,
  tagNameProcessors: [XMLProcessors.normalize, XMLProcessors.stripPrefix]
}

const validators = {

}

/**
 * @typedef {Object} CAS_options
 * @property {string}  cas_url
 * @property {string}  service_url
 * @property {('1.0'|'2.0'|'3.0'|'saml1.1')} [cas_version='3.0']
 * @property {boolean} [renew=false]
 * @property {boolean} [is_dev_mode=false]
 * @property {string}  [dev_mode_user='']
 * @property {Object}  [dev_mode_info={}]
 * @property {string}  [session_name='cas_user']
 * @property {string}  [session_info=false]
 * @property {boolean} [destroy_session=false]
 */

/**
 * @param {CAS_options} options
 * @constructor
 */
function CASAuthentication (options) {
  if (!options || typeof options !== 'object') {
    throw new Error('CAS Authentication was not given a valid configuration object.')
  }
  if (options.cas_url === undefined) {
    throw new Error('CAS Authentication requires a cas_url parameter.')
  }
  if (options.service_url === undefined) {
    throw new Error('CAS Authentication requires a service_url parameter.')
  }

  this.cas_version = options.cas_version !== undefined ? options.cas_version : '3.0'

  if (this.cas_version === '1.0') {
    this._validateUri = '/validate'
    this._validate = (body, callback) => {
      const lines = body.split('\n')
      if (lines[0] === 'yes' && lines.length >= 2) {
        callback(null, lines[1])
      } else if (lines[0] === 'no') {
        callback(new Error('CAS authentication failed.'))
      } else {
        callback(new Error('Response from CAS server was bad.'))
      }
    }
  } else if (this.cas_version === '2.0' || this.cas_version === '3.0') {
    this._validateUri = (this.cas_version === '2.0' ? '/serviceValidate' : '/p3/serviceValidate')
    this._validate = (body, callback) => {
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
          console.log(err)
          callback(new Error('CAS authentication failed.'))
        }
      })
    }
  } else if (this.cas_version === 'saml1.1') {
    this._validateUri = '/samlValidate'
    this._validate = (body, callback) => {
      parseXML(body, XML_PROCESSORS_CONFIG, (err, result) => {
        if (err) {
          callback(new Error('Response from CAS server was bad.'))
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
          console.log(err)
          callback(new Error('CAS authentication failed.'))
        }
      })
    }
  } else {
    throw new Error('The supplied CAS version ("' + this.cas_version + '") is not supported.')
  }

  const parsed_cas_url = new URL(options.cas_url)
  this.request_client = parsed_cas_url.protocol === 'http:' ? http : https
  this.cas_port = parsed_cas_url.port || parsed_cas_url.protocol === 'http:' ? 80 : 443
  this.cas_host = parsed_cas_url.hostname
  this.cas_path = parsed_cas_url.pathname

  this.service_url = options.service_url
  this.return_to = options.return_to
  this.cas_url = options.cas_url

  this.renew = options.renew !== undefined ? !!options.renew : false
  this.session_name = options.session_name !== undefined ? options.session_name : 'cas_user'
  this.session_info = ['2.0', '3.0', 'saml1.1'].indexOf(this.cas_version) >= 0 && options.session_info !== undefined ? options.session_info : false
  this.destroy_session = options.destroy_session !== undefined ? !!options.destroy_session : false

  this.is_dev_mode = options.is_dev_mode !== undefined ? !!options.is_dev_mode : false
  this.dev_mode_user = options.dev_mode_user !== undefined ? options.dev_mode_user : ''
  this.dev_mode_info = options.dev_mode_info !== undefined ? options.dev_mode_info : {}

  // Bind the prototype routing methods to this instance of CASAuthentication.
  this.bounce = this.bounce.bind(this)
  this.bounce_redirect = this.bounce_redirect.bind(this)
  this.block = this.block.bind(this)
  this.logout = this.logout.bind(this)
}

/**
 * Bounces a request with CAS authentication. If the user's session is not
 * already validated with CAS, their request will be redirected to the CAS
 * login page.
 */
CASAuthentication.prototype.bounce = (req, res, next) => {
  // Handle the request with the bounce authorization type.
  this._handle(req, res, next, AUTH_TYPE.BOUNCE)
}

/**
 * Bounces a request with CAS authentication. If the user's session is not
 * already validated with CAS, their request will be redirected to the CAS
 * login page.
 */
CASAuthentication.prototype.bounce_redirect = (req, res, next) => {
  // Handle the request with the bounce authorization type.
  this._handle(req, res, next, AUTH_TYPE.BOUNCE_REDIRECT)
}

/**
 * Blocks a request with CAS authentication. If the user's session is not
 * already validated with CAS, they will receive a 401 response.
 */
CASAuthentication.prototype.block = (req, res, next) => {
  // Handle the request with the block authorization type.
  this._handle(req, res, next, AUTH_TYPE.BLOCK)
}

/**
 * Handle a request with CAS authentication.
 */
CASAuthentication.prototype._handle = (req, res, next, authType) => {
  // If the session has been validated with CAS, no action is required.
  if (req.session[this.session_name]) {
    // If this is a bounce redirect, redirect the authenticated user.
    if (authType === AUTH_TYPE.BOUNCE_REDIRECT) {
      res.redirect(req.session.cas_return_to)

    // Otherwise, allow them through to their request.
    } else {
      next()
    }

  // If dev mode is active, set the CAS user to the specified dev user.
  } else if (this.is_dev_mode) {
    req.session[this.session_name] = this.dev_mode_user
    req.session[this.session_info] = this.dev_mode_info
    next()

  // If the authentication type is BLOCK, simply send a 401 response.
  } else if (authType === AUTH_TYPE.BLOCK) {
    res.sendStatus(401)

  // If there is a CAS ticket in the query string, validate it with the CAS server.
  } else if (req.query && req.query.ticket) {
    this._handleTicket(req, res, next)

  // Otherwise, redirect the user to the CAS login.
  } else {
    this._login(req, res, next)
  }
}

/**
 * Redirects the client to the CAS login.
 */
CASAuthentication.prototype._login = (req, res, next) => {
  // Save the return URL in the session. If an explicit return URL is set as a
  // query parameter, use that. Otherwise, just use the URL from the request.
  const request_url = new URL(req.url)
  req.session.cas_return_to = req.query.returnTo || this.return_to || request_url.path

  // Set up the query parameters.
  const query = {
    service: this.service_url + request_url.pathname,
    renew: this.renew
  }

  // Redirect to the CAS login.
  res.redirect(this.cas_url + URL.format({
    pathname: '/login',
    query: query
  }))
}

/**
 * Logout the currently logged in CAS user.
 */
CASAuthentication.prototype.logout = (req, res, next) => {
  // Destroy the entire session if the option is set.
  if (this.destroy_session) {
    if (req.session.destroy) {
      req.session.destroy(function (err) {
        if (err) {
          console.log(err)
        }
      })
    } else {
      req.session[this.session_name] = null
    }

  // Otherwise, just destroy the CAS session variables.
  } else {
    delete req.session[this.session_name]
    if (this.session_info) {
      delete req.session[this.session_info]
    }
  }

  // Redirect the client to the CAS logout.
  res.redirect(this.cas_url + '/logout')
}

/**
 * Handles the ticket generated by the CAS login requester and validates it with the CAS login acceptor.
 */
CASAuthentication.prototype._handleTicket = (req, res) => {
  const requestUrl = new URL(req.url)
  const requestOptions = {
    host: this.cas_host,
    port: this.cas_port
  }

  let post_data = null

  if (['1.0', '2.0', '3.0'].indexOf(this.cas_version) >= 0) {
    requestOptions.method = 'GET'
    requestOptions.path = URL.format({
      pathname: this.cas_path + this._validateUri,
      query: {
        service: this.service_url + requestUrl.pathname,
        ticket: req.query.ticket
      }
    })
  } else if (this.cas_version === 'saml1.1') {
    const now = new Date()
    post_data = `\
<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header/>
  <SOAP-ENV:Body>
    <samlp:Request
      xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
      MajorVersion="1"
      MinorVersion="1"
      RequestID="_${req.host}.${now.getTime()}"
      IssueInstant="${now.toISOString()}"
    >
      <samlp:AssertionArtifact>
        ${req.query.ticket}
      </samlp:AssertionArtifact>
    </samlp:Request>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
`
    requestOptions.method = 'POST'
    requestOptions.path = URL.format({
      pathname: this.cas_path + this._validateUri,
      query: {
        TARGET: this.service_url + requestUrl.pathname,
        ticket: ''
      }
    })
    requestOptions.headers = {
      'Content-Type': 'text/xml',
      'Content-Length': Buffer.byteLength(post_data)
    }
  }

  const request = this.request_client.request(requestOptions, function (response) {
    response.setEncoding('utf8')
    let body = ''

    response.on('data', function (chunk) {
      body += chunk
      return body
    })

    response.on('end', function () {
      this._validate('', function (err, user, attributes) {
        if (err) {
          console.log(err)
          res.sendStatus(401)
        } else {
          req.session[this.session_name] = user
          if (this.session_info) {
            req.session[this.session_info] = attributes || {}
          }
          res.redirect(req.session.cas_return_to)
        }
      }.bind(this))
    }.bind(this))

    response.on('error', function (err) {
      console.log('Response error from CAS: ', err)
      res.sendStatus(401)
    })
  }.bind(this))

  request.on('error', function (err) {
    console.log('Request error with CAS: ', err)
    res.sendStatus(401)
  })

  if (this.cas_version === 'saml1.1') {
    request.write(post_data)
  }

  request.end()
}

module.exports = CASAuthentication
