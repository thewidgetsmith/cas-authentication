/**
 * NodeCAS client.js
 */
'use strict'

const debug = require('debug')('node-cas:client')
const http = require('http')
const https = require('https')

const { AUTH_TYPE, CAS_PROTOCOL } = require('./constants')
const { getCasValidatorParameters } = require('./validators')
const { getCasTicketHandler } = require('./functions')

/**
 * Express next() middleware function
 * @callback ExpressNext
 */

/**
 * NodeCAS configuration options
 * @typedef {Object} Options
 * @property {('1.0'|'2.0'|'3.0'|'saml1.1')} [casVersion='3.0'] - The CAS Protocol Version name, determines the validation URL and TicketValidator function.
 * @property {string}  casServerUrlPrefix       - The start of the CAS server URL (may include port for non-standard ports), i.e. https://login.example.com/cas.
 * @property {string}  serverName               - The name of the server this application is hosted on i.e. https://my.webapp.com/login/return.
 * @property {('GET'|'POST')} method            - The method used by the CAS server to send the user back to the application.
 * @property {boolean} [renew=false]            - Specifies whether `renew=true` should be sent to the CAS server.
 *
 * @property {boolean} [destroySession=false]   - Specifies whether the CAS User session should be destroyed upon logout.
 * @property {string}  [sessionInfo=false]      -
 * @property {string}  [sessionName='cas_user'] -
 *
 * @property {boolean} [devModeActive=false]    - Specifies whether NodeCAS should run in development mode.
 * @property {Object}  [devModeInfo={}]         - The dev mode user information
 * @property {string}  [devModeUser='']         - The dev mode username
 */

/**
 * NodeCAS client for Apereo CAS.
 *
 * @param {Options} options
 */
class NodeCAS {
  constructor (options) {
    debug('NodeCAS constructor', options)
    if (!(options) || typeof options !== 'object') {
      throw new Error('NodeCAS was not given a valid configuration object.')
    }
    if (options.casServerUrl === undefined) {
      throw new Error('NodeCAS requires a casServerUrl parameter.')
    }
    if (options.service === undefined) {
      throw new Error('NodeCAS requires a service parameter.')
    }

    const casVersion = options.casVersion || CAS_PROTOCOL.CAS_3_0
    const validator = getCasValidatorParameters(casVersion)
    const handler = getCasTicketHandler(casVersion)
    this.validateUrl = validator.url
    this.validator = validator.fn
    this.handler = handler.fn

    const parsedCasUrl = new URL(options.casServerUrl)
    this.requestClient = parsedCasUrl.protocol === 'http:' ? http : https
    this.casServerUrl = options.casServerUrl
    this.casHost = parsedCasUrl.hostname
    this.casPath = parsedCasUrl.pathname
    this.casPort = parsedCasUrl.port
    this.casUrl = options.casUrl

    this.renew = !!(options.renew)
    this.returnTo = options.returnTo
    this.service = options.service

    this.destroySession = !!(options.destroySession)
    this.sessionInfo = options.sessionInfo || false
    this.sessionName = options.sessionName || 'cas_user'

    this.devModeActive = !!(options.devModeActive)
    this.devModeInfo = options.devModeInfo || {}
    this.devModeUser = options.devModeUser || ''

    this.block = this.block.bind(this)
    this.bounce = this.bounce.bind(this)
    this.bounceRedirect = this.bounceRedirect.bind(this)
    this.logout = this.logout.bind(this)
  }

  /**
   * CAS login request handler method
   * @param {Express.Request} req
   * @param {Express.Response} res
   * @param {ExpressNext} next
   * @param {string} authType
   */
  _handle (req, res, next, authType) {
    debug('_handle/SESSION', { session: req.session, sessionName: this.sessionName })
    // If the session has been validated with CAS, no action is required.
    if (req.session[this.sessionName]) {
      // If this is a bounce redirect, redirect the authenticated user.
      if (authType === AUTH_TYPE.BOUNCE_REDIRECT) {
        res.redirect(req.session.casReturnTo)

      // Otherwise, allow them through to their request.
      } else {
        next()
      }

    // If dev mode is active, set the CAS user to the specified dev user.
    } else if (this.devModeActive) {
      req.session[this.sessionName] = this.devModeUser
      req.session[this.sessionInfo] = this.devModeInfo
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
   * CAS ticket handler method
   * @param {Express.Request} req
   * @param {Express.Response} res
   */
  _handleTicket (req, res) {
    debug('_handleTicket/TICKET', { path: req.path, url: req.url })
    let post_data = null
    const casRequest = {
      options: {},
      url: ''
    }

  // if (['1.0', '2.0', '3.0'].indexOf(this.cas_version) >= 0) {
      const search = new URLSearchParams({
        service: this.service,
        ticket: req.query.ticket
      })

      const reqUrl = new URL(`${this.casServerUrl}/${this.validateUrl}`)
      reqUrl.search = search

      casRequest.url = reqUrl.href
      casRequest.options.method = 'GET'
  //   } else if (this.cas_version === 'saml1.1') {
  //     const now = new Date()
  //     post_data = `\
  // <?xml version="1.0" encoding="utf-8"?>
  // <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  //   <SOAP-ENV:Header/>
  //   <SOAP-ENV:Body>
  //     <samlp:Request
  //       xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
  //       MajorVersion="1"
  //       MinorVersion="1"
  //       RequestID="_${req.host}.${now.getTime()}"
  //       IssueInstant="${now.toISOString()}"
  //     >
  //       <samlp:AssertionArtifact>
  //         ${req.query.ticket}
  //       </samlp:AssertionArtifact>
  //     </samlp:Request>
  //   </SOAP-ENV:Body>
  // </SOAP-ENV:Envelope>
  // `
  //     const search = new URLSearchParams({
  //       TARGET: this.service_url, // + req.path,
  //       ticket: ''
  //     })

  //     const reqUrl = new URL(this.cas_url + this._validateUri)
  //     reqUrl.search = search

  //     casRequest.url = reqUrl.href
  //     casRequest.options.method = 'POST'
  //     casRequest.options.headers = {
  //       'Content-Type': 'text/xml',
  //       'Content-Length': Buffer.byteLength(post_data)
  //     }
  //   }

    // console.log('_handleTicket/REQ_OPTS', casRequest)

    const request = this.requestClient.request(
      casRequest.url,
      casRequest.options,
      function (response) {
        response.setEncoding('utf8')
        let body = ''

        response.on('data', function (chunk) {
          // console.log('_handleTicket/CHUNK', '' + chunk)
          return body += chunk
          // return body
        })

        response.on('end', function () {
          this.validator(body, function (err, user, attributes) {
            if (err) {
              console.log(err)
              res.sendStatus(401)
              return
            }

            req.session[this.sessionName] = user
            if (this.sessionInfo) {
              req.session[this.sessionInfo] = attributes || {}
            }

            // console.log('_handleTicket/RESPONSE/end', { body, user, session: req.session })

            res.redirect(req.session.casReturnTo)
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

    // if (this.cas_version === 'saml1.1') {
    //   request.write(post_data)
    // }

    request.end()
  }

  /**
   * Redirects the client to the CAS login.
   *
   * @param {Express.Request} req
   * @param {Express.Response} res
   * @param {ExpressNext} next
   */
  _login (req, res, next) {
    // Save the return URL in the session. If an explicit return URL is set as a
    // query parameter, use that. Otherwise, just use the URL from the request.
    req.session.casReturnTo = req.query.returnTo || this.returnTo || req.path

    // Construct the CAS login redirect URL
    const redirect = new URL(`${this.casServerUrl}/login`)
    redirect.search = new URLSearchParams({
      service: this.service,
      renew: this.renew
    })

    // Redirect to the CAS login.
    res.redirect(redirect.href)
  }

  /**
   * Blocks a request with CAS authentication. If the user's session is not
   * already validated with CAS, they will receive a 401 response.
   *
   * @param {Express.Request} req
   * @param {Express.Response} res
   * @param {ExpressNext} next
   */
  block (req, res, next) {
    // Handle the request with the block authorization type.
    this._handle(req, res, next, AUTH_TYPE.BLOCK)
  }

  /**
   * Bounces a request with CAS authentication. If the user's session is not
   * already validated with CAS, their request will be redirected to the CAS
   * login page.
   *
   * @param {Express.Request} req
   * @param {Express.Response} res
   * @param {ExpressNext} next
   */
  bounce (req, res, next) {
    // Handle the request with the bounce authorization type.
    this._handle(req, res, next, AUTH_TYPE.BOUNCE)
  }

  /**
   * Bounces a request with CAS authentication. If the user's session is not
   * already validated with CAS, their request will be redirected to the CAS
   * login page.
   *
   * @param {Express.Request} req
   * @param {Express.Response} res
   * @param {ExpressNext} next
   */
  bounceRedirect (req, res, next) {
    // Handle the request with the bounce authorization type.
    this._handle(req, res, next, AUTH_TYPE.BOUNCE_REDIRECT)
  }

  /**
   * Logout the currently logged in CAS user.
   *
   * @param {Express.Request} req
   * @param {Express.Response} res
   * @param {ExpressNext} next
   */
  logout (req, res, next) {
    // Destroy the entire session if the option is set.
    if (this.destroySession) {
      if (req.session.destroy) {
        req.session.destroy(function (err) {
          if (err) {
            console.log(err)
          }
        })
      } else {
        req.session[this.sessionName] = null
      }

    // Otherwise, just destroy the CAS session variables.
    } else {
      delete req.session[this.sessionName]
      if (this.sessionInfo) {
        delete req.session[this.sessionInfo]
      }
    }

    // Redirect the client to the CAS logout.
    res.redirect(`${this.casServerUrl}/logout`)
  }
}

module.exports = NodeCAS
