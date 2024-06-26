const netlify = {
  clientIdKey: "NETLIFY_OAUTH_CLIENT_ID",
  clientSecretKey: "NETLIFY_OAUTH_CLIENT_SECRET",

  /* OAuth API endpoints */
  tokenHost: 'https://api.netlify.com',
  tokenPath: 'https://api.netlify.com/oauth/token',
  authorizePath: 'https://app.netlify.com/authorize',

  /* User API endpoint */
  userApi: "https://api.netlify.com/api/v1/user/",
};

// https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps
const github = {
  clientIdKey: "GITHUB_OAUTH_CLIENT_ID",
  clientSecretKey: "GITHUB_OAUTH_CLIENT_SECRET",

  /* OAuth API endpoints */
  tokenHost: "https://github.com/",
  tokenPath: "https://github.com/login/oauth/access_token",
  authorizePath: "https://github.com/login/oauth/authorize",

  /* User API endpoint */
  userApi: "https://api.github.com/user",
};

// https://docs.gitlab.com/ee/api/oauth2.html
const gitlab = {
  clientIdKey: "GITLAB_OAUTH_CLIENT_ID",
  clientSecretKey: "GITLAB_OAUTH_CLIENT_SECRET",

  /* OAuth API endpoints */
  tokenHost: "https://gitlab.com/",
  tokenPath: "https://gitlab.com/oauth/token",
  authorizePath: "https://gitlab.com/oauth/authorize",

  /* Scope of access to request */
  scope: 'read_user',

  /* User API endpoint */
  userApi: "https://gitlab.com/api/v4/user",
  
}

const slack = {
  clientIdKey: "SLACK_OAUTH_CLIENT_ID",
  clientSecretKey: "SLACK_OAUTH_CLIENT_SECRET",

  /* OAuth API endpoints */
  tokenHost: "https://slack.com/",
  tokenPath: "https://slack.com/api/openid.connect.token",
  authorizePath: "https://slack.com/openid/connect/authorize",

  /* Scope of access to request */
  scope: 'openid email profile',

  /* User API endpoint */
  userApi: "https://slack.com/api/openid.connect.userInfo",
}

const linkedin = {
  clientIdKey: "LINKEDIN_OAUTH_CLIENT_ID",
  clientSecretKey: "LINKEDIN_OAUTH_CLIENT_SECRET",

  /* OAuth API endpoints */
  tokenHost: "https://linkedin.com/",
  tokenPath: "https://www.linkedin.com/oauth/v2/accessToken",
  authorizePath: "https://www.linkedin.com/oauth/v2/authorization",

  /* Scope of access to request */
  scope: 'r_liteprofile r_emailaddress',

  /* User API endpoint */
  userApi: "https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName,profilePicture(displayImage~digitalmediaAsset:playableStreams))",
}

// https://api.stackexchange.com/docs/authentication
const stackexchange = {
  clientIdKey: "STACKEXCHANGE_OAUTH_CLIENT_ID",
  clientSecretKey: "STACKEXCHANGE_OAUTH_CLIENT_SECRET",

  /* OAuth API endpoints */
  tokenHost: 'https://stackoverflow.com',
  tokenPath: 'https://stackoverflow.com/oauth/access_token/json',
  authorizePath: 'https://stackoverflow.com/oauth',

  /* Key to receive higher request quota */
  quotaKey: "STACKEXCHANGE_KEY",
  
  /* User API endpoint */
  userApi: "https://api.stackexchange.com/2.3/me?order=desc&sort=reputation&site=stackoverflow",
};

module.exports = {
  netlify,
  github,
  gitlab,
  slack,
  linkedin,
  stackexchange
};
