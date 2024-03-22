const { AuthorizationCode } = require('simple-oauth2');
const cookie = require("cookie");
const fetch = require('node-fetch')
const zlib = require('zlib');


// Warning: process.env.DEPLOY_PRIME_URL won’t work in a Netlify function here.
const SITE_URL = process.env.URL || 'http://localhost:8888';

const providers = require('./providers.js');

class OAuth {
  constructor(provider) {
    this.provider = provider;

    let config = this.config;
    this.authorizationCode = new AuthorizationCode({
      client: {
        id: config.clientId,
        secret: config.clientSecret
      },
      auth: {
        tokenHost: config.tokenHost,
        tokenPath: config.tokenPath,
        authorizePath: config.authorizePath
      }
    });
  }

  get config() {
    const cfg = {
      secureHost: SITE_URL,
      sessionExpiration: 60 * 60 * 8, // in seconds, this is 8 hours

      /* redirect_uri is the callback url after successful signin */
      redirect_uri: `${SITE_URL}/.netlify/functions/auth-callback`,
    }

    if(this.provider === "netlify") {
      Object.assign(cfg, providers.netlify);
    } else if(this.provider === "github") {
      Object.assign(cfg, providers.github);
    } else if(this.provider === "gitlab") {
      Object.assign(cfg, providers.gitlab);
    } else if(this.provider === "slack") {
      Object.assign(cfg, providers.slack);
    } else if(this.provider === "linkedin") {
      Object.assign(cfg, providers.linkedin);
    } else if(this.provider === "stackexchange") {
      Object.assign(cfg, providers.stackexchange);
    } else {
      throw new Error("Invalid provider passed to OAuth. Currently only `netlify`, `github`, `gitlab`, `slack`, `linkedin` or `stackexchange` are supported.")
    }

    cfg.clientId = process.env[cfg.clientIdKey];
    cfg.clientSecret = process.env[cfg.clientSecretKey];

    if( this.provider === "stackexchange" ){
      if (!cfg.clientId || !cfg.clientSecret || !cfg.quotaKey) {
          throw new Error(`MISSING REQUIRED ENV VARS. ${cfg.clientIdKey}, ${cfg.clientSecretKey} and ${cfg.quotaKey} are required.`)
        }
    } else {  
      if (!cfg.clientId || !cfg.clientSecret) {
        throw new Error(`MISSING REQUIRED ENV VARS. ${cfg.clientIdKey} and ${cfg.clientSecretKey} are required.`)
      }
    }

    return cfg;
  }

  async getUser(token) {
    if(!token) {
      throw new Error("Missing authorization token.");
    }
    const provider = this.config.provider;
    const access_token = this.config.access_token;
    const quotaKey = this.config.quotaKey;
    const url = provider === "stackexchange"
      ? `this.config.userApi&access_token=${access_token}&key=${quotakey}` 
      : this.config.userApi;
    const options = provider === "stackexchange"
    ?  {
      method: 'GET',
      headers: {
        'Accept-Encoding': 'gzip',       
      }
    : {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      }
    const response = await fetch(url, options)
    })
  
    console.log( "[auth] getUser response status", response.status );
    if (response.status !== 200) {
      throw new Error(`Error ${await response.text()}`)
    }

    let data;
    if( provider === "stackexchange"){      
      const gzi = zlib.gzipSync(response.data);
      data = zlib.gunzipSync(
        new Buffer.from(gzi)).toString(); 
    } else {
      data = await response.json();
    }
    return data
  }
}

function getCookie(name, value, expiration) {
  let options = {
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    path: '/',
    maxAge: expiration,
  };

  // no strict cookies on localhost for local dev
  if(SITE_URL.startsWith("http://localhost:8888")) {
    delete options.sameSite;
  }

  return cookie.serialize(name, value, options)
}

function generateCsrfToken() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8) // eslint-disable-line
    return v.toString(16)
  })
}

module.exports = {
  OAuth,
  tokens: {
    encode: function(token) {
      return Buffer.from(token, "utf8").toString("base64");
    },
    decode: function(token) {
      return Buffer.from(token, "base64").toString("utf8");
    }
  },
  getCookie,
  generateCsrfToken,
}
