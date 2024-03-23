const cookie = require("cookie");
const querystring = require("querystring");
const { OAuth, tokens, getCookie } = require("./util/auth.js");


// Function to handle netlify auth callback
exports.handler = async (event, context) => {
  // Exit early
  if (!event.queryStringParameters) {
    return {
      statusCode: 401,
      body: JSON.stringify({
        error: 'Not authorized',
      })
    }
  }

  // Grant the grant code
  const code = event.queryStringParameters.code;

  // state helps mitigate CSRF attacks & Restore the previous state of your app
  const state = querystring.parse(event.queryStringParameters.state)

  try {
    // console.log( "[auth-callback] Cookies", event.headers.cookie );
    let cookies = event.headers.cookie ? cookie.parse(event.headers.cookie) : {};
    if(cookies._11ty_oauth_csrf !== state.csrf) {
      throw new Error("Missing or invalid CSRF token.");
    }

    let oauth = new OAuth(state.provider);
    let config = oauth.config;

    // Take the grant code and exchange for an accessToken
    let accessToken, token;
    if(state.provider === "stackexchange") {
      const url = config.tokenPath;
      const data = {
        code: code,
        redirect_uri: config.redirect_uri,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        state: event.queryStringParameters.state
      };
      let formBody = [];
      for (let property in data) {
        const encodedKey = encodeURIComponent(property);
        const encodedValue = encodeURIComponent(data[property]);
        formBody.push(encodedKey + "=" + encodedValue);
      }
      formBody = formBody.join("&");
      const options = {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: formBody
      } 
      console.log(`${url}, ${JSON.stringify(options)}`) 
      const response = await fetch(url, options);
      const accessToken = await response.json();
      if(await response.status === 200){
        token = accessToken.access_token;
        console.log('token: ' + token);
      } else {
        throw new Error(await response.statusText);
      }
    } else {
      accessToken = await oauth.authorizationCode.getToken({
        code: code,
        redirect_uri: config.redirect_uri,
        client_id: config.clientId,
        client_secret: config.clientSecret
      });

      token = accessToken.token.access_token;
      console.log( "[auth-callback]", { token } );
    }
    // The noop key here is to workaround Netlify keeping query params on redirects
    // https://answers.netlify.com/t/changes-to-redirects-with-query-string-parameters-are-coming/23436/11
    const URI = `${state.url}?noop`;
    // console.log( "[auth-callback]", { URI });

    /* Redirect user to authorizationURI */
    return {
      statusCode: 302,
      headers: {
        Location: URI,
        'Cache-Control': 'no-cache' // Disable caching of this response
      },
      multiValueHeaders: {
        'Set-Cookie': [
          // This cookie *must* be HttpOnly
          (state.provider === "stackexchange") 
            ? getCookie("_11ty_oauth_token", token, oauth.config.sessionExpiration)
            : getCookie("_11ty_oauth_token", tokens.encode(token), oauth.config.sessionExpiration),
          getCookie("_11ty_oauth_provider", state.provider, oauth.config.sessionExpiration),
          getCookie("_11ty_oauth_csrf", "", -1),
        ]
      },
      body: '' // return body for local dev
    }
  
  } catch (e) {
    console.log("[auth-callback]", 'Access Token Error', e.message)
    console.log("[auth-callback]", e)
    return {
      statusCode: e.statusCode || 500,
      body: JSON.stringify({
        error: e.message,
      })
    }
  }
}
