# Auth Proxy

This project intends to remove identity complexity around authentication and authorization as much as possible from web application developers, and instead encapsulate identity protocols, authentication flows, authentication cookies, token acquisition and caching, ... in a completely separate process which sits in front of the app as a reverse proxy. This allows the web application to offload those concerns to an independent layer which embodies best practices and which can be updated separately as identity standards and patterns evolve. The application itself then only needs to work through simple native HTTP constructs and API's to receive and request identity-related information from the proxy.

## How Does It Work?

The proxy is driven completely by [configuration](#configuration).

To get started, you declare one or more [Identity Providers (IdPs)](#identity-providers) with the typical details like its URL, which protocol it uses (such as OpenID Connect, OAuth 2.0, SAML 2.0 or WS-Federation), and protocol-specific values such as a client ID and client secret, scopes, allowed token audiences, ... Where it makes sense (for example to make use of vendor-specific features), you can also configure the specific *type* of IdP instead of the protocol (for example, declare that it's [Azure Active Directory](https://docs.microsoft.com/azure/active-directory/fundamentals/active-directory-whatis) or [Auth0](https://auth0.com/)).

Now when you deploy the reverse proxy in front of your backend app (for example, by pointing the DNS records of your domain name to the proxy instead of your app), it will transparently forward all traffic to the app - except when it sees a request coming in that's intended for the proxy itself.

### Logging In

To allow a user to log in, the backend app can render a link to the appropriate login URL on the proxy (by default this is `/.auth/login`). When the user clicks that link, the proxy intercepts the request. Now rather than forwarding it to the backend app, it redirects the browser to the configured IdP instead. Once the user has successfully authenticated, the proxy then sets a session cookie to keep the user logged in for subsequent requests and redirects the browser back to the app.

As of then, the proxy adds HTTP headers towards the backend app with information about the authenticated user by means of a standard [JWT token](https://datatracker.ietf.org/doc/html/rfc7519). The app therefore only needs to be able to work with standard JWT bearer tokens (which is traditionally supported in most platforms) and never has to deal with identity protocols, redirect flows, session cookies, ...

This process is illustrated in a **[swimlane diagram of a typical login flow](https://swimlanes.io/u/q2ktfBSZG)**.

Alternatively to providing a login link, you can also configure [inbound policies](#inbound-policies) to specify which paths in the application should be authenticated, so that a request for `/account` for example will always ensure that the user is logged in before even being able to reach that URL on the backend app.

### Accessing protected resources

When the backend app wants to call a downstream service secured by one of its IdPs, it typically needs to acquire an access token to authorize the request. In this case, rather than dealing with the complexity of token acquisition, caching, security, lifetime, refresh tokens, ... it can simply use a "callback" API exposed by the reverse proxy instead. In this case, the backend app can perform a simple HTTP request towards `/.auth/api/token` with certain request details (such as which scopes are requested in the token) and the proxy will do all the work to obtain a valid access token and return it to the app.

For improved security, it's even possible to avoid exposure of the token (which is a security credential, in the end) to the backend app altogether, by using the "forward" API at `/.auth/api/forward`. In this case, the backend app sends an HTTP request *as if it were intended for the downstream service* - except that it sends it to the proxy and adds a specific HTTP header with the *intended destination* of the request. By configuring an [outbound policy](#outbound-policies) on the proxy, it knows to acquire an appropriate token for that destination. The proxy acquires the token and appends it as an authorization header on the outgoing request towards the downstream service. The backend app simply receives the response from the service without even having to deal with tokens at all.

This process is illustrated in a **[swimlane diagram of a typical scenario with an inbound policy as well as use of the "forward" and "token" APIs](https://swimlanes.io/u/ucJZKyx6z)**.

## Guiding Principles

- **Provide a single abstraction towards the backend app for one or more Identity Providers (IdPs)** that end users can login with and for which the app can acquire tokens.
  - For example, the app generally shouldn't care if the user just authenticated with the IdP, or if the request was authenticated through a session cookie for a subsequent call.
  - The backend app also shouldn't care if the user was logged in with OpenID Connect, SAML, WS-Federation or any other supported protocol; the same information is presented to the app in the same format regardless of the IdP and protocol being used.
  - By default, the proxy passes this information to the app by injecting a standard authorization header with a JWT token. This token contains claims with all relevant information for the backend app. This means the backend app only needs to use standard JWT middleware or libraries to authenticate the user, and never has to deal with identity protocols, login flows, sessions, ... It only cares about a single trusted token issuer which is the proxy itself, and it can validate its tokens through standard mechanisms such as relying on the OpenID Connect metadata exposed by the proxy.
- **Interact with the backend app only through a stable HTTP based "contract"**, primarily relying on HTTP headers for passing information and (when needed) an easy-to-use API.
  - For example, each request to the backend app will always have the same claims as part of the authorization header, regardless of how authentication was performed.
  - If the app needs to request an access token, it can call back into the proxy using an API which takes care of acquiring, caching and refreshing tokens.
  - For increased security, the backend app can even use an API on the proxy to let it forward an HTTP request to an external service; the proxy will then attach the right token for the destination service without the app ever needing to have access to the token itself.
- **Don't host a user interface**, meaning that the proxy should never "present itself" to a user but only work between the IdP and backend app.
  - For example, in case there are multiple IdPs for users to login with, it's up to the backend app to provide the necessary UI to allow the user to choose. The app then redirects to the appropriate endpoint on the proxy for authenticating the user with the chosen IdP.
  - Because the proxy doesn't need to generate any HTML, it doesn't need to deal with branding, localization, accessibility, ...

## Functionality

In the sections below, note that:

- [X] A checked box indicates that a feature is already available in the proxy.
- [ ] An unchecked box indicates it's planned but not yet implemented.

### Deployment

For maximum flexibility, the proxy can be deployed in many ways:

- [X] As a self-hosted application (i.e. build and run the proxy however you want).
- [ ] As a prebuilt container (such as a reverse proxy "sidecar" container deployed next to the backend app, for example as a service mesh in Kubernetes).
- [ ] As a [Dapr](https://dapr.io/) component or middleware.
- [ ] As built-in functionality of hosting platforms (for example, in theory it should be able to replace the proprietary [Azure App Service "Easy Auth"](https://docs.microsoft.com/azure/app-service/overview-authentication-authorization) functionality as a fully managed offering, by hosting this open source project directly on the platform in front of customer apps).

### Security

The communication channel between the proxy and the backend app should be secured so that the app can be certain it's not receiving identity information from a malicious sender. This can be done as follows:

- [X] The JWT token which the proxy sends to the app can be validated by standard middleware, relying on the signing keys of the proxy exposed through its OpenID Connect metadata endpoint.
- [X] Network access control on the infrastructure hosting the backend app or within the app itself, to only allow requests from the IP address of the proxy (this is not the responsibility of the proxy itself).
- [ ] Client certificate authentication on the HTTP requests between the proxy and the backend app.

For the callback APIs which the proxy hosts, the backend app also needs to authenticate to avoid that malicious clients can request tokens or perform other privileged operations that should only be allowed by the backend app. This can be done as follows:

- [X] Authorization to the callback APIs using standard JWT access tokens.
- [X] Network access control on the infrastructure hosting the proxy, to only allow requests from the IP address of the backend app (this is not the responsibility of the proxy itself).
- [ ] Network access control within the proxy itself to only allow requests from the IP address of the backend app.
- [ ] Client certificate authentication on the HTTP requests between the backend app and the proxy.

In order to simplify security for the callback APIs between the backend web app and the proxy, the required authorization token which the app needs is already provided as an incoming HTTP header in each request coming from the proxy. This means that the backend app simply needs to get the value of the `X-AuthProxy-Callback-AuthorizationHeader-Value` header and send that back as the value of the standard `Authorization` HTTP header on any API request to the proxy. Similar to the JWT token that contains authentication information intended for the backend app, this token is also signed by the proxy's own signing keys so it cannot be forged by a malicious client.

### HTTP "Contract"

#### Backend App Headers

Information about the user is provided to the backend app in a standard `Authorization` HTTP header, with a `Bearer` JWT token containing the relevant (and configured) claims. The JWT can be validated in the backend app by standard JWT middleware, which is typically configured from an OpenID Connect metadata URL which the proxy exposes at `/.well-known/openid-configuration`.

Next to that, the proxy also injects other HTTP headers towards the backend app, for example with an authorization token for the callback APIs as explained in the [security section](#security). The backend app simply needs to send this header value back to the proxy when performing an API request.

#### Token API

The proxy exposes an API at `/.auth/api/token` to allow the backend app to acquire tokens. It expects an HTTP GET request with a few parameters:

- `identityProvider`: the reference name of the [configured IdP](#identity-providers) from which to acquire a token.
- `actor`: indicates whether the token should be acquired on behalf of the user of the current request, on behalf of the app itself (using its client credentials), or other vendor-specific options (such as using [managed identities for Azure resources](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview)).
- `scopes`: defines which scopes should be requested when acquiring the token.
- `returnUrl`: in case the token could not be silently acquired (for example, the user hasn't consented to the requested scopes yet, or MFA is required for some scopes), the proxy will return a redirect URL towards the IdP; it's then up to the app to redirect the browser to this URL. In such case the `returnUrl` specified here will be used to redirect the user back to after they have successfully authenticated with the IdP.

Instead of passing in all these properties, the backend app can also include a single `profile` parameter which references a configured [token request profile](#token-request-profiles) on the proxy. This abstracts away the details from the backend app and allows it just to refer to a logical name of a certain scenario for which it needs a token.

For an example of using the Token API, see the [CallApi](src/TestWebApp/Pages/CallApi.cshtml.cs) page of the sample app.

##### Token API: Example Request

The example below shows the backend app making a callback API request against the "token" endpoint. It has the authorization header set to the bearer token it received as an HTTP header from the proxy, and a request object which allows the proxy to acquire a token from `aad` (the reference name of the configured IdP), on behalf of the currently authenticated user, for a scope of `user.read` and with a specific return URL in case the token could not be acquired.

```http
POST /.auth/api/token HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
...
{
  "identityProvider": "aad",
  "actor": "User",
  "scopes": [ "user.read" ],
  "returnUrl": "https://example.org/..."
}
```

##### Token API: Example Response

If the proxy already had a token for the user matching the request, or if it had a refresh token to acquire such a token silently, or if the actor was the app itself rather than a user, it would be able to return the token directly to the backend app:

```json
{
  "status": "Succeeded",
  "token": "eyJ0eXAiOiJKV1QiLCJu..."
}
```

##### Token API: Example Redirect Response

In case the proxy couldn't acquire the token silently and user interaction is required, it will return a response with the complete redirect URL which triggers the appropriate login for the IdP.

```json
{
  "status": "RedirectRequired",
  "redirectUrl": "https://login.microsoftonline.com/example.org/oauth2/v2.0/authorize?client_id=...",
  "redirectCookies": [ ... ]
}
```

When authentication is complete, the proxy will redirect the browser back to the specified `returnUrl` of the original request. In that case, the backend app can retry the token request.

#### Forward API

The proxy exposes an API at `/.auth/api/forward` to allow the backend app to forward calls to external HTTP services. When a service is configured via an [outbound policy](#outbound-policies), the proxy will see the HTTP request coming in for a configured destination, it acquires the necessary token (also in this case the details are configured in a [token request profile](#token-request-profiles)), and attaches it as a bearer token on the outgoing HTTP request it sends to the external service.

The Forward API can be called exactly like the final destination would get called (meaning, all HTTP methods, headers and body as usual), with the only difference being that the immediate request is sent from the backend app to the reverse proxy rather than the destination service. You then provide the final destination as an `X-AuthProxy-Destination` HTTP header so the proxy knows where to send the final request to.

Similar to the [Token API](#token-api), in case the proxy cannot silently acquire the token, the backend app must redirect the browser back to the IdP for authentication. The return URL where to redirect the browser afterwards is specified by the backend app in the `X-AuthProxy-ReturnUrl` HTTP header.

For an example of using the Forward API, see the [CallApi](src/TestWebApp/Pages/CallApi.cshtml.cs) page of the sample app.

##### Forward API: Example Request

The example below shows the backend app making a callback API request towards the "forward" endpoint. It has the authorization header set to the bearer token it received as an HTTP header from the proxy, as well as the `X-AuthProxy-Destination` header set to the intended destination service (in this case, the Microsoft Graph API) and the `X-AuthProxy-ReturnUrl` header set to a return URL in case user interaction is required. Everything else should be *exactly* as the final destination service expects, as the proxy forwards it as-is.

```http
GET /.auth/api/forward HTTP/1.1
Host: localhost:7268
Authorization: Bearer eyJhbGciOi...
X-AuthProxy-Destination: https://graph.microsoft.com/v1.0/me
X-AuthProxy-ReturnUrl: https://example.org/...
```

##### Forward API: Example Response

In case the proxy was able to acquire the required token silently, the response that is sent back to the backend app will be the exact response as received from the external service.

##### Forward API: Example Redirect Response

In case the proxy couldn't acquire the token silently and user interaction is required, it will return an HTTP status code `511 Network Authentication Required` along with additional HTTP headers such as the redirect URL to be used by the backend app, as before.

```http
HTTP/1.1 511 Network Authentication Required
X-AuthProxy-Status: RedirectRequired
X-AuthProxy-RedirectUrl: https://login.microsoftonline.com/example.org/oauth2/v2.0/authorize?client_id=...
X-AuthProxy-RedirectCookies: ...
```

#### Dynamic Actions

Some decisions aren't static or configuration-driven, such as triggering a stronger form of authentication based on business logic (for example, requiring MFA when the user is about to confirm a financial transaction). The app can then instruct the proxy to perform certain functionality, for example by returning specific HTTP headers to the proxy to trigger an authentication challenge:

- `X-AuthProxy-Action: Challenge`
- `X-AuthProxy-ReturnUrl: /foo/bar`

The proxy will see these headers coming back on the HTTP response and take appropriate action, for example by building the redirect URL for the IdP in this case, and returning a redirect response to the browser instead.

### Client SDK

To make it easier to build apps using the reverse proxy, a client SDK for all major runtimes/languages (.NET, Java, Python, Go, ...) can be foreseen to:

- [ ] Request information from the proxy (e.g. to [acquire a token](#token-api), or [perform an outbound call](#forward-api) for which the proxy attaches the token).
- [ ] Trigger [dynamic actions](#dynamic-actions) by returning the right HTTP headers to the proxy.
- [ ] Auto-wire certain common functionality with identity based information; for example: for .NET apps the SDK could set the [SqlConnection.AccessToken](https://docs.microsoft.com/dotnet/api/system.data.sqlclient.sqlconnection.accesstoken) property to a token acquired from the proxy.

### Configuration

For maximum flexibility, the proxy is intended to be *insanely configurable*. For example, the available IdPs, protocols, scopes, anonymous versus authenticated paths, external services, login and API endpoints, ... can all be changed via configuration. Because you should be able to host the proxy in a variety of ways and update it independently from the backend app, its implementation should be considered a black box which is driven purely from configuration.

All the necessary configuration can be provided via:

- [X] Configuration files
- [X] Environment variables
- [ ] An external API endpoint (which is called at startup)

For an example configuration file, see [appsettings.json](src/AuthProxy/appsettings.json).

#### Token Issuer

Given that the proxy creates and signs its own JWT tokens, it must be configured with certain details such as the expiration time for those tokens and which X509 certificate(s) to use for the token signature.

These details are then exposed through the proxy's OpenID Connect metadata endpoint so that the backend app can validate the tokens.

#### Backend App

The proxy is configured with a (single) backend app, which contains the URL where requests need to be forwarded to. It also specifies which host name to send to the backend app: either passing through the original host of the incoming request, overriding it with the host name of the backend app URL, or setting it to a specific host name.

#### Authentication Cookie

You can configure the name of the authentication session cookie issued by the proxy, as well as define whether or not it's a persistent cookie that is stored beyond the current browser session.

#### Identity Providers

You can define one or more IdPs which the proxy can use to log users in or acquire tokens from. You give each IdP a reference name, so that you can refer to it in URLs and from other places like [token request profiles](#token-request-profiles). IdPs using any of the following identity protocols are supported:

- [X] OpenID Connect
- [ ] OAuth 2.0
- [ ] SAML 2.0
- [ ] WS-Federation

Furthermore, you can also define an IdP to be a specific type which allows the proxy to use vendor-specific functionality:

- [X] Azure Active Directory
  - [X] Support [incremental or dynamic consent when using the Microsoft identity platform](https://docs.microsoft.com/azure/active-directory/develop/v2-permissions-and-consent#incremental-and-dynamic-user-consent).
  - [X] Acquire tokens for [managed identities for Azure resources](https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview).
  - [ ] Support [workload identity federation](https://docs.microsoft.com/azure/active-directory/develop/workload-identity-federation).
  - [ ] Support [conditional access evaluation in Azure AD](https://docs.microsoft.com/azure/active-directory/conditional-access/concept-continuous-access-evaluation).
- [X] Azure AD B2C
  - [X] Work with [user flows or custom policies in Azure AD B2C](https://docs.microsoft.com/azure/active-directory-b2c/user-flow-overview).
- [ ] Google
  - [ ] Support [workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation).
- [ ] Auth0
  - [ ] Work with [Auth0 Organizations](https://auth0.com/docs/manage-users/organizations).

Depending on the protocol or type of IdP, you configure the typical properties like its client ID and client secret, and which response type, scopes, audiences, ... to use.

By default (but this can be changed in configuration as well), each IdP gets a login URL on the proxy at `/.auth/login/<name>`, for example `/.auth/login/aad` if the reference name of the IdP is `aad`. You can also configure a "default" IdP which simply uses `/.auth/login`.

The proxy uses incoming claims from the IdP to generate the appropriate information that will be sent to the backend app. Each type of IdP has a default set of claims mappings, which can be further customized in configuration by using [claims transformations](#claims-transformations).

- For OpenId Connect, the proxy uses the claims of the `id_token` (*not* an `access_token` for a downstream service as this is opaque to the client and shouldn't carry *authentication* information for the app).
- For JWT bearer authorization, the proxy uses the claims from the incoming bearer token (typically an OAuth 2.0 `access_token` intended for this relying party).
- For SAML 2.0 protocol and WS-Federation, the proxy uses the assertions in the SAML token.

At a minimum, the proxy creates a `sub` claim that the backend app can rely on for uniquely identifying the user, typically by combining a unique identifier of the user within the IdP, along with a unique identifier of the IdP itself. For example, in the case of OpenID Connect the user is identified using the standard `sub` (subject) claim, and the IdP using the standard `iss` (issuer) claim. By default, these are combined into `sub + '@' + iss` and sent to the backend app as the final `sub` claim.

#### Token Request Profiles

If the backend app uses the [Token API](#token-api) to request tokens from the proxy, it can specify all the required information in the request. However, it's also possible to avoid tight coupling of the app code with token or protocol details. The API request can then simply refer to a configured token request profile which defines the IdP, actor (user or app), scopes and return URL.

Token request profiles are also used from [outbound policies](#outbound-policies).

#### Inbound Policies

Inbound policies allow you to specify certain application paths for which the proxy should take action. If a request comes in that matches one of these inbound policies, the proxy will for example ensure the user is authenticated without the backend app even getting called or having to redirect the user to a certain IdP's login endpoint.

Each inbound policy defines a list of path patterns, an action to take (always allow anonymous access, require authentication, or always block the request), and a list of IdPs which are allowed to access that path.

For example, you can use inbound policies to ensure requests for `/admin` need to be authenticated with your organization's IdP, but that requests for `/consumer` are authenticated with a social IdP.

#### Outbound Policies

When using the [Forward API](#forward-api), the backend app specifies the intended destination for which the proxy should attach a token.

Each outbound policy specifies a URL pattern to match against the requested destination, an action to take (attaching a bearer token), and the name of the [token request profile](#token-request-profiles) which contains the details of the token to acquire.

### Claims Transformations

#### Syntax

The claims that are sent to the backend app are pre-configured for each IdP type but can be fully customized via claims transformation expressions.

Each expression returns an output claim based on a transformation expression in the form:

`output=<transformation>`

As a shorthand to return the same output claim as an input claim, you can specify just the name of that claim. For example, adding an expression `email` will send the original `email` value(s) of the IdP to the backend app.

An *empty* `<transformation>` means that *no* output will be returned; this can be useful when you want to remove an output claim that was generated by default. For example, adding an expression `iss=` (note the `=` sign at the end to differentiate it from the shorthand syntax explained above) ensures that no `iss` claim will be sent to the backend app.

#### Inputs

The following inputs can be used in transformations:

- [X] `string['value']` or simply `'value'`: returns a constant string value.
- [X] `claim[type]` or simply `type`: returns incoming claim values for the specified claim `type`.
- [ ] `config[name]`: returns a configuration value.
- [ ] `idp[name]`: returns information about the IdP that authenticated the user.

The following `config` names are available:

- [ ] `config[issuer]`: the configured `issuer` value used by the proxy.
- [ ] `config[audience]`: the configured `audience` value that represents the backend app.

The following `idp` names are available:

- [ ] `idp[name]`: the `name` of the IdP that authenticated the user.
- [ ] `idp[type]`: the `type` of the IdP that authenticated the user.

Note that if there are multiple claim values for a claim type in the expression, or even multiple claim types in the expression which each have multiple claim values, the output claim will have values for the Cartesian product of all input claim values. See the examples below for details.

#### Functions

- [X] `+`: concatenates strings.
- [ ] `split(input, separator)`: splits the `input` claim value(s) into multiple values based on the specified `separator` string.
- [ ] `join(input, separator)`: returns one claim value with the concatenated values of all original `input` claim values, joined with the specified `separator` string.

#### Examples

Given the following input claims (in JSON format):

```json
{
  "sub": "user123",
  "iss": "https://example.org",
  "scp": "openid profile email",
  "roles": [ "reader", "writer" ]
}
```

The following example expressions can be constructed:

| Expression                                   | Output (in JSON format)                                                                                                        | Explanation                                                                         |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `sub`                                        | `{ "sub": "user123" }`                                                                                                         | Returns the original `sub` claim value (shorthand syntax for the entire expression) |
| `sub=sub`                                    | `{ "sub": "user123" }`                                                                                                         | Returns the original `sub` claim value (shorthand syntax for the claim type)        |
| `sub=claim[sub]`                             | `{ "sub": "user123" }`                                                                                                         | Returns the original `sub` claim value (full syntax)                                |
| `roles`                                      | `{ "roles": [ "reader", "writer" ] }`                                                                                          | Returns all the original `roles` claim values                                       |
| `sub=`                                       | (None)                                                                                                                         | Removes the `sub` claim value so it won't be sent to the backend app                |
| `ver='1.0'`                                  | `{ "ver": "1.0" }`                                                                                                             | Returns a `ver` claim with a constant value (shorthand syntax for the string value) |
| `ver=string['1.0']`                          | `{ "ver": "1.0" }`                                                                                                             | Returns a `ver` claim with a constant value                                         |
| `sub=sub + '@' + iss`                        | `{ "sub": "user123@https://example.org" }`                                                                                     | Concatenates the original `sub` claim with an `@` character and the `iss` claim     |
| `scp=split(scp, ' ')`                        | `{ "scp": [ "openid", "profile", "email" ] }`                                                                                  | Splits values of the `scp` claim by a space into multiple `scp` claims              |
| `roles=join(roles, ' ')`                     | `{ "roles": "reader writer" }`                                                                                                 | Joins multiple  `roles` claims into a single `roles` value separated by a space     |
| `idp=idp[name]`                              | `{ "idp": "example.org" }`                                                                                                     | Returns the name of the IdP that authenticated the user as the `idp-name` claim     |
| `scopes-roles=split(scp, ' ') + '-' + roles` | `{ "scopes-roles": [ "openid-reader", "openid-writer", "profile-reader", "profile-writer", "email-reader", "email-writer" ] }` | Returns the Cartesian product of all the (split) scopes and roles                   |

## Related Projects

- There are other similar implementations but they don't go as deep and they're a part of other stacks, for example:
  - [Ambassador Edge Stack](https://www.getambassador.io/docs/edge-stack/latest/howtos/oauth-oidc-auth/).
  - [OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy).
- [App Service "Easy Auth"](https://docs.microsoft.com/azure/app-service/overview-authentication-authorization).
  - This is a vendor-specific implementation of the concept but provides a lot less functionality and flexibility.
- [Dapr](https://dapr.io/) has some of this functionality but built-in to the Dapr sidecar itself (not externalized/pluggable as another sidecar).
  - [Dapr middleware](https://docs.dapr.io/reference/components-reference/supported-middleware/)
  - [OAuth2](https://github.com/dapr/components-contrib/blob/master/middleware/http/oauth2/oauth2_middleware.go) supports an authorization code exchange and then puts the acquired token on the call to the actual Dapr service.
    - However, it doesn't perform token caching, inspection/validation of the token (audience, timestamps, ...), or other operations that are typically required.
  - [OAuth2 Client Credentials](https://github.com/dapr/components-contrib/blob/master/middleware/http/oauth2clientcredentials/oauth2clientcredentials_middleware.go) supports token caching, but only works with client secret (no certificate or managed identity or other authentication mechanism).
  - [Bearer](https://github.com/dapr/components-contrib/blob/master/middleware/http/bearer/bearer_middleware.go) "validates" tokens but performs only very limited validation against OpenID Connect metadata (which doesn't seem cached either, which could be a performance hit).
