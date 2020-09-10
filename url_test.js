'use strict'

const http = require('http')
const https = require('https')

const myUrl = new URL('https://google.com:9090?foo=bar#baz')
console.log('URL', myUrl.port)
