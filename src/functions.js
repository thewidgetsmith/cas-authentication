/**
 * CAS Ticket Handler Functions
 */
'use strict'

const debug = require('debug')('node-cas:handler')
const { CAS_PROTOCOL } = require('./constants')

// if (['1.0', '2.0', '3.0'].indexOf(this.cas_version) >= 0) {
  // const search = new URLSearchParams({
  //   service: this.service,
  //   ticket: req.query.ticket
  // })

  // const reqUrl = new URL(`${this.casServerUrl}/${this.validateUrl}`)
  // reqUrl.search = search

  // casRequest.url = reqUrl.href
  // casRequest.options.method = 'GET'
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


const CasTicketHandler = function () {

}

const SamlTicketHandler = function () {

}

exports.getCasTicketHandler = function (casVersion) {
  switch (casVersion) {
    case CAS_PROTOCOL.CAS_1_0:
    case CAS_PROTOCOL.CAS_2_0:
    case CAS_PROTOCOL.CAS_3_0:
      return {
        fn: CasTicketHandler
      }

    case CAS_PROTOCOL.SAML_1_1:
      return {
        fn: SamlTicketHandler
      }

    default:
      throw new Error(`CAS Protocol version '${casVersion}' is invalid. Refer to the documentation for allowed versions.`)
  }
}
