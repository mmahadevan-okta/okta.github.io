---
layout: docs_page
title: OAuth 2.0
---

# Overview

The OAuth 2.0 API endpoints enable clients to use [OAuth 2.0 workflows](https://tools.ietf.org/html/rfc6749) with Okta.
This authorization layer separates the role of client from that of resource owner by providing the client with an Access Token
that can define scope, lifetime, and other attributes. 

Additionally, these endpoints support the use of [OpenID Connect](/docs/api/resources/oidc.html) for OpenID Connect workflows such as social authentication.

> This API is currently in **Early Access** status.  It has been tested as thoroughly as a Generally Available feature. Contact Support to enable this feature.

Okta is the identity provider responsible for verifying the identity of users and applications that exist in an organization’s directory, 
and ultimately issuing access tokens upon successful authentication of those users and applications. 

The basic authentication flow with Okta as the identity provider:

1. The client sends an authorization request to Okta's authorization server in reference to a resource owner.
2. Okta verifies the client with the resource owner, and if successful, returns an authorization grant to the client.
3. The client receives the authorization grant, whose type depends on how the client requested authorization. 
4. The client sends the authorization grant to Okta's authorization server and requests an  Access Token.
5. Okta approves or denies the requested scopes.
6. Okta authenticates the client, validates the authorization grant, and if valid, mints an Access Token and sends it in the response. 

> Important: Okta uses public key cryptography to sign tokens and verify that they are valid. 
See the last section of [Access Tokens](#access-tokens) for more information on the logic your application must have to ensure it’s always updated with the latest keys.

The properties you need depend on which client profile and use case you are targeting, as explained in [Choosing the Right Workflow](choosing-the-right-workflow).

## Claims

ID tokens issued by Okta contain claims, which are statements about a subject (user).  
For example, the claim can be about a name, identity, key, group, or privilege. The claims in a security token are dependent upon the type of token, 
the type of credential used to authenticate the user, and the application configuration.

## Supported OAuth 2.0 flows

Okta supports the following OAuth 2.0 flows, which are documented in the [OAuth spec](https://tools.ietf.org/html/rfc6749):

* Implicit flow for client-side web applications such as single-page apps or server-side apps with an end user
* Authorization code flow for server-side web applications such as when access must be long-lived, or the client is a web application server, or whenever the Access Token shouldn't be shared with the browser
* Client Credentials flow for clients that don't need delegated access in the OAuth flow
* Hybrid flows, documented in [OpenID Connect](#openid.html)

### Implicit flow

![Implicit flow with OAuth 2.0, no OpenID Connect](/assets/img/implicit_oauth20.png)

### Authorization code flow

![Authorization code flow with OAuth 2.0, no OpenID Connect](/assets/img/auth_code_flow.png)

### Client credential code flow

![Client credential flow with OAuth 2.0, no OpenID Connect](/assets/img/client_cred_flow.png)

\* The Access Token request is made by providing an authentication code, client ID, credential, redirect URI and App ID URI.

\** The Access Token is returned with a refresh token, so the client doesn't have to repeat authentication steps.
    
### Native App Requirements
 
Be aware of two important requirements for native apps:
 
* For native applications, the *client_id* and *client_secret* are embedded in the source code of the application. Thus, *client_secret* is not a secret.
* Native apps must use [PKCE](https://tools.ietf.org/html/rfc7636) to mitigate authorization code interception. For more information, see [OAuth2.0](http://developer.okta.com/docs/api/resources/oauth2#parameter-details).

### Tokens and Flows

Using Oauth 2.0 and Okta to manage authentication and authorization involves the use of different tokens.
Each token serves a particular part of a flow, and has different behaviors and contents.

![Tokens, OAuth, and Okta](/assets/img/tokens_and_flows1.png)

Scopes are defined in the request parameter, and claims are in the Access Token returned from the request.

>For more information about OpenID Connect and ID Tokens, see [OpenID Connect](/docs/api/resources/oidc.html). They are included here for completeness.

* ID Tokens are returned with all requests to `/oauth2/v1/authorize`. In addition to reserve scopes and claims, ID Tokens contain an authorization grant.
* Access Tokens and Refresh tokens are returned from requests to `/oauth2/v1/token` if the request contains an authorization code or Refresh Token.

### Tokens and Scopes

Okta provides pre-defined scopes called reserve scopes that you can specify in the request. Use the `scope` parameter to define the scopes, any
combination of `openid`, `profile`, `email`, `address`, and `phone`. <<link to that section when merged>>

You can also define your own custom scopes in the request. <<link to section when merged>>

## Endpoints

### Authentication Request
{:.api .api-operation}

<span class="api-uri-template api-uri-get"><span class="api-label">GET</span> /oauth2/v1/authorize</span>

Starting point for all OAuth 2.0 flows. This request authenticates the user and returns an ID Token along with an authorization grant to the client application as a part of the response the client might have requested.

#### Request Parameters
{:.api .api-request .api-request-params}

Parameter         | Description                                                                                        | Param Type | DataType  | Required | Default         |
----------------- | -------------------------------------------------------------------------------------------------- | ---------- | --------- | -------- | --------------- |
[idp](idps.html)               | The Identity provider used to do the authentication. If omitted, use Okta as the identity provider. | Query      | String    | FALSE    | Okta is the IDP. |
sessionToken      | An Okta one-time sessionToken. This allows an API-based user login flow (rather than Okta login UI). Session tokens can be obtained via the [Authentication API](authn.html).   | Query | String    | FALSE | |             
response_type     | Can be a combination of *code*, *token*, and *id_token*. The chosen combination determines which flow is used; see this reference from the [OIDC specification](http://openid.net/specs/openid-connect-core-1_0.html#Authentication). The code response type returns an authorization code which can be later exchanged for an Access Token or a Refresh Token. | Query        | String   |   TRUE   |  |
client_id         | Obtained during either [UI client registration](../../guides/social_authentication.html) or [API client registration](oauth-clients.html). It is the identifier for the client and it must match what is preregistered in Okta. | Query        | String   | TRUE     | 
redirect_uri      | Specifies the callback location where the authorization code should be sent and it must match what is preregistered in Okta as a part of client registration. | Query        | String   |  TRUE    | 
display           | Specifies how to display the authentication and consent UI. Valid values: *page* or *popup*.  | Query        | String   | FALSE     |  |
max_age           | Specifies the allowable elapsed time, in seconds, since the last time the end user was actively authenticated by Okta. | Query      | String    | FALSE    | |
response_mode     | Specifies how the authorization response should be returned. [Valid values: *fragment*, *form_post*, *query* or *okta_post_message*](#parameter-details). If *id_token* is specified as the response type, then *query* can't be used as the response mode. Default: Defaults to and is required to be *fragment* in implicit and hybrid flow. Defaults to *query* in authorization code flow. | Query        | String   | FALSE      | See Description.
scope          | Can be a combination of *openid*, *profile*, *email*, *address* and *phone*. The combination determines the claims that are returned in the id_token. The openid scope has to be specified to get back an id_token. | Query        | String   | TRUE     | 
state          | A client application provided state string that might be useful to the application upon receipt of the response. It can contain alphanumeric, comma, period, underscore and hyphen characters.   | Query        | String   |  TRUE    | 
prompt         | Can be either *none* or *login*. The value determines if Okta should not prompt for authentication (if needed), or force a prompt (even if the user had an existing session). Default: The default behavior is based on whether there's an existing Okta session. | Query        | String   | FALSE     | See Description. 
nonce          | Specifies a nonce that is reflected back in the ID Token. It is used to mitigate replay attacks. | Query        | String   | TRUE     | 
code_challenge | Specifies a challenge of [PKCE](#parameter-details). The challenge is verified in the Access Token request.  | Query        | String   | FALSE    | 
code_challenge_method | Specifies the method that was used to derive the code challenge. Only S256 is supported.  | Query        | String   | FALSE    | 

#### Parameter Details
 
 * *idp* and *sessionToken* are Okta extensions to the [OIDC specification](http://openid.net/specs/openid-connect-core-1_0.html#Authentication). 
    All other parameters comply with the [OAuth 2.0 specification](https://tools.ietf.org/html/rfc6749) and their behavior is consistent with the specification.
 * Each value for *response_mode* delivers different behavior:
    * *fragment* -- Parameters are encoded in the URL fragment added to the *redirect_uri* when redirecting back to the client.
    * *query* -- Parameters are encoded in the query string added to the *redirect_uri* when redirecting back to the client.
    * *form_post* -- Parameters are encoded as HTML form values that are auto-submitted in the User Agent.Thus, the values are transmitted via the HTTP POST method to the client
      and the result parameters are encoded in the body using the application/x-www-form-urlencoded format.
    * *okta_post_message* -- Uses [HTML5 Web Messaging](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) (for example, window.postMessage()) instead of the redirect for the authorization response from the authorization endpoint.
      *okta_post_message* is an adaptation of the [Web Message Response Mode](https://tools.ietf.org/html/draft-sakimura-oauth-wmrm-00#section-4.1). 
      This value provides a secure way for a single-page application to perform a sign-in flow 
      in a popup window or an iFrame and receive the ID token and/or access token back in the parent page without leaving the context of that page.
      The data model for the [postMessage](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) call is in the next section.
      
 * Okta requires the OAuth 2.0 *state* parameter on all requests to the authorization endpoint in order to prevent cross-site request forgery (CSRF). 
 The OAuth 2.0 specification [requires](https://tools.ietf.org/html/rfc6749#section-10.12) that clients protect their redirect URIs against CSRF by sending a value in the authorize request which binds the request to the user-agent's authenticated state. 
 Using the *state* parameter is also a countermeasure to several other known attacks as outlined in [OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819).

 * [Proof Key for Code Exchange](https://tools.ietf.org/html/rfc7636) (PKCE) is a stronger mechanism for binding the authorization code to the client than just a client secret, and prevents [a code interception attack](https://tools.ietf.org/html/rfc7636#section-1) if both the code and the client credentials are intercepted (which can happen on mobile/native devices). The PKCE-enabled client creates a large random string as code_verifier and derives code_challenge from it using code_challenge_method. It passes the code_challenge and code_challenge_method in the authorization request for code flow. When a client tries to redeem the code, it must pass the code_verifer. Okta recomputes the challenge and returns the requested token only if it matches the code_challenge in the original authorization request. When a client, whose token_endpoint_auth_method is 'none', makes a code flow authorization request, the code_challenge parameter is required.
      
#### postMessage() Data Model

Use the postMessage() data model to help you when working with the *okta_post_message* value of the *response_mode* request parameter.

*message*:

Parameter         | Description                                                                                        | DataType  | 
----------------- | -------------------------------------------------------------------------------------------------- | ----------| 
id_token          | The ID Token JWT contains the details of the authentication event and the claims corresponding to the requested scopes. This is returned if the `response_type` includes `id_token`. | String   |
access_token      | The *access_token* used to access the [`/oauth2/v1/userinfo`](/docs/api/resources/oidc.html#get-user-information) endpoint. This is returned if the *response_type* included a token. <b>Important</b>: Unlike the ID Token JWT, the *access_token* structure is specific to Okta, and is subject to change. | String    |
state             | If the request contained a `state` parameter, then the same unmodified value is returned back in the response. | String    |
error             | The error-code string providing information if anything goes wrong.                                | String    |
error_description | Additional description of the error.                                                               | String    |

*targetOrigin*: 

Specifies what the origin of *parentWindow* must be in order for the postMessage() event to be dispatched
(this is enforced by the browser). The *okta-post-message* response mode always uses the origin from the *redirect_uri* 
specified by the client. This is crucial to prevent the sensitive token data from being exposed to a malicious site.

#### Response Parameters

The response depends on the response type passed to the API. For example, a *fragment* response mode returns values in the fragment portion of a redirect to the specified *redirect_uri* while a *form_post* response mode POSTs the return values to the redirect URI. 
Irrespective of the response type, the contents of the response is always one of the following.

Parameter         | Description                                                                                        | DataType  | 
----------------- | -------------------------------------------------------------------------------------------------- | ----------| 
id_token          | The ID Token JWT contains the details of the authentication event and the claims corresponding to the requested scopes. This is returned if the *response_type* includes *id_token* .| String    | 
access_token      | The *access_token* that is used to access the [`/oauth2/v1/userinfo`](/docs/api/resources/oidc.html#get-user-information) endpoint. This is returned if the *response_type*  included a token. Unlike the ID Token JWT, the *access_token* structure is specific to Okta, and is subject to change.| String  |
token_type        | The token type is always `Bearer` and is returned only when *token* is specified as a *response_type*. | String |
state             | The same unmodified value from the request is returned back in the response. | String |
error             | The error-code string providing information if anything went wrong. | String |
error_description | Further description of the error. | String |

##### Possible Errors

These APIs are compliant with the OpenID Connect and OAuth2 spec with some Okta specific extensions. 

[OAuth 2 Spec error codes](https://tools.ietf.org/html/rfc6749#section-4.1.2.1)

Error Id         | Details                                                                | 
-----------------| -----------------------------------------------------------------------| 
unsupported_response_type  | The specified response type is invalid or unsupported.   | 
unsupported_response_mode  | The specified response mode is invalid or unsupported. This error is also thrown for disallowed response modes. For example, if the query response mode is specified for a response type that includes id_token.    | 
invalid_scope   | The scopes list contains an invalid or unsupported value.    | 
server_error    | The server encountered an internal error.    | 
temporarily_unavailable    | The server is temporarily unavailable, but should be able to process the request at a later time.    |
invalid_request | The request is missing a necessary parameter or the parameter has an invalid value. |
invalid_grant   | The specified grant is invalid, expired, revoked, or does not match the redirect URI used in the authorization request.
invalid_token   | The provided access token is invalid.
invalid_client  | The specified client id is invalid.
access_denied   | The server denied the request. 

[Open-ID Spec error codes](http://openid.net/specs/openid-connect-core-1_0.html#AuthError)

Error Id           | Details                                                                | 
-------------------| -----------------------------------------------------------------------| 
login_required     | The request specified that no prompt should be shown but the user is currently not authenticated.    |
insufficient_scope | The access token provided does not contain the necessary scopes to access the resource.              |

#### Response Example (Success)

The request is made with a *fragment* response mode.

~~~
http://www.example.com/#
id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwMHVpZDRCeFh3Nkk2VFY0bTBnMyIsImVtYWlsIjoid2VibWFzdGVyQGNsb3VkaXR1ZG
UubmV0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInZlciI6MSwiaXNzIjoiaHR0cDovL3JhaW4ub2t0YTEuY29tOjE4MDIiLCJsb2dpbiI6ImFkbWluaXN
0cmF0b3IxQGNsb3VkaXR1ZGUubmV0IiwiYXVkIjoidUFhdW5vZldrYURKeHVrQ0ZlQngiLCJpYXQiOjE0NDk2MjQwMjYsImV4cCI6MTQ0OTYyNzYyNiwi
YW1yIjpbInB3ZCJdLCJqdGkiOiI0ZUFXSk9DTUIzU1g4WGV3RGZWUiIsImF1dGhfdGltZSI6MTQ0OTYyNDAyNiwiYXRfaGFzaCI6ImNwcUtmZFFBNWVIO
DkxRmY1b0pyX1EifQ.Btw6bUbZhRa89DsBb8KmL9rfhku--_mbNC2pgC8yu8obJnwO12nFBepui9KzbpJhGM91PqJwi_AylE6rp-ehamfnUAO4JL14Pke
mF45Pn3u_6KKwxJnxcWxLvMuuisnvIs7NScKpOAab6ayZU0VL8W6XAijQmnYTtMWQfSuaaR8rYOaWHrffh3OypvDdrQuYacbkT0csxdrayXfBG3UF5-ZA
lhfch1fhFT3yZFdWwzkSDc0BGygfiFyNhCezfyT454wbciSZgrA9ROeHkfPCaX7KCFO8GgQEkGRoQntFBNjluFhNLJIUkEFovEDlfuB4tv_M8BM75celd
y3jkpOurg
&access_token=eyJhbGciOiJSUzI1NiJ9.eyJ2ZXIiOjEsImlzcyI6Imh0dHA6Ly9yYWluLm9rdGExLmNvbToxODAyIiwiaWF0
IjoxNDQ5NjI0MDI2LCJleHAiOjE0NDk2Mjc2MjYsImp0aSI6IlVmU0lURzZCVVNfdHA3N21BTjJxIiwic2NvcGVzIjpbIm9wZW5pZCIsImVtYWlsIl0sI
mNsaWVudF9pZCI6InVBYXVub2ZXa2FESnh1a0NGZUJ4IiwidXNlcl9pZCI6IjAwdWlkNEJ4WHc2STZUVjRtMGczIn0.HaBu5oQxdVCIvea88HPgr2O5ev
qZlCT4UXH4UKhJnZ5px-ArNRqwhxXWhHJisslswjPpMkx1IgrudQIjzGYbtLFjrrg2ueiU5-YfmKuJuD6O2yPWGTsV7X6i7ABT6P-t8PRz_RNbk-U1GXW
IEkNnEWbPqYDAm_Ofh7iW0Y8WDA5ez1jbtMvd-oXMvJLctRiACrTMLJQ2e5HkbUFxgXQ_rFPNHJbNSUBDLqdi2rg_ND64DLRlXRY7hupNsvWGo0gF4WEU
k8IZeaLjKw8UoIs-ETEwJlAMcvkhoVVOsN5dPAaEKvbyvPC1hUGXb4uuThlwdD3ECJrtwgKqLqcWonNtiw
&token_type=Bearer&state=waojafoawjgvbf
~~~

#### Response Example (Error)

The requested scope is invalid:

~~~
http://www.example.com/#error=invalid_scope&error_description=The+requested+scope+is+invalid%2C+unknown%2C+or+malformed
~~~

### Token Request
{:.api .api-operation}

<span class="api-uri-template api-uri-get"><span class="api-label">POST</span> /oauth2/v1/token</span>

The API takes an authorization code or a Refresh Token as the grant type and returns back an Access Token, ID Token and a Refresh Token.

> Note:  No errors occur if you use this endpoint, but it isn’t useful until custom scopes or resource servers are available. We recommend you wait until custom scopes and resource servers are available.

#### Request Parameters

The following parameters can be posted as a part of the URL-encoded form values to the API.

Parameter          | Description                                                                                         | Type       |
-------------------+-----------------------------------------------------------------------------------------------------+------------|
grant_type         | Can be one of the following: *authorization_code*, *password*, or *refresh_token*. Determines the mechanism Okta will use to authorize the creation of the tokens. | String |  
code               | Expected if grant_type specified *authorization_code*. The value is what was returned from the /oauth2/v1/authorize endpoint. | String
refresh_token      | Expected if the grant_type specified *refresh_token*. The value is what was returned from this endpoint via a previous invocation. | String |
scope              | Expected only if *refresh_token* is specified as the grant type. This is a list of scopes that the client wants to be included in the Access Token. These scopes have to be subset of the scopes used to generate the Refresh Token in the first place. | String |
redirect_uri       | Expected if grant_type is *authorization_code*. Specifies the callback location where the authorization was sent; must match what is preregistered in Okta for this client. | String |
code_verifier      | The code verifier of [PKCE](#parameter-details). Okta uses it to recompute the code_challenge and verify if it matches the original code_challenge in the authorization request. | String |


##### Token Authentication Method

The client can authenticate by providing the [`client_id`](oidc.html#request-parameters) 
and [`client_secret`](https://support.okta.com/help/articles/Knowledge_Article/Using-OpenID-Connect) as an Authorization header in the Basic auth scheme (basic authentication).

For authentication with Basic auth, an HTTP header with the following format must be provided with the POST request.

~~~sh
Authorization: Basic ${Base64(<client_id>:<client_secret>)} 
~~~

#### Response Parameters

Based on the grant type, the returned JSON contains a different set of tokens.

Input grant type   | Output token types                    |
-------------------|---------------------------------------|
authorization_code | ID Token, Access Token, Refresh Token |
refresh_token      | Access Token, Refresh Token           |

##### Refresh Tokens for Web and Native Applications

For web and native application types, an additional process is required:

1. Use the Okta Administration UI and check the <b>Refresh Token</b> checkbox under <b>Allowed Grant Types</b> on the client application page.
2. Pass the *offline_access* scope to your authorize request.

#### List of Errors 

Error Id                |  Details                                                                                                     |
------------------------+--------------------------------------------------------------------------------------------------------------|
invalid_client          | The specified client id wasn't found. |
invalid_request         | The request structure was invalid. E.g. the basic authentication header was malformed, or both header and form parameters were used for authentication or no authentication information was provided. |
invalid_grant           | The *code* or *refresh_token* value was invalid, or the *redirect_uri* does not match the one used in the authorization request. |
unsupported_grant_type  | The grant_type was not *authorization_code* or *refresh_token*. |

#### Response Example (Success)

~~~json
{
    "access_token" : "eyJhbGciOiJSUzI1NiJ9.eyJ2ZXIiOjEsImlzcyI6Imh0dHA6Ly9yYWluLm9rdGExLmNvbToxODAyIiwiaWF0IjoxNDQ5Nj
                      I0MDI2LCJleHAiOjE0NDk2Mjc2MjYsImp0aSI6IlVmU0lURzZCVVNfdHA3N21BTjJxIiwic2NvcGVzIjpbIm9wZW5pZCIsI
                      mVtYWlsIl0sImNsaWVudF9pZCI6InVBYXVub2ZXa2FESnh1a0NGZUJ4IiwidXNlcl9pZCI6IjAwdWlkNEJ4WHc2STZUVjRt
                      MGczIn0.HaBu5oQxdVCIvea88HPgr2O5evqZlCT4UXH4UKhJnZ5px-ArNRqwhxXWhHJisslswjPpMkx1IgrudQIjzGYbtLF
                      jrrg2ueiU5-YfmKuJuD6O2yPWGTsV7X6i7ABT6P-t8PRz_RNbk-U1GXWIEkNnEWbPqYDAm_Ofh7iW0Y8WDA5ez1jbtMvd-o
                      XMvJLctRiACrTMLJQ2e5HkbUFxgXQ_rFPNHJbNSUBDLqdi2rg_ND64DLRlXRY7hupNsvWGo0gF4WEUk8IZeaLjKw8UoIs-E
                      TEwJlAMcvkhoVVOsN5dPAaEKvbyvPC1hUGXb4uuThlwdD3ECJrtwgKqLqcWonNtiw",
    "token_type" : "Bearer",
    "expires_in" : 3600,
    "refresh_token" : "a9VpZDRCeFh3Nkk2VdY",
    "id_token" : "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwMHVpZDRCeFh3Nkk2VFY0bTBnMyIsImVtYWlsIjoid2VibWFzdGVyQGNsb3VkaXR1ZG
                  UubmV0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInZlciI6MSwiaXNzIjoiaHR0cDovL3JhaW4ub2t0YTEuY29tOjE4MDIiLCJsb
                  2dpbiI6ImFkbWluaXN0cmF0b3IxQGNsb3VkaXR1ZGUubmV0IiwiYXVkIjoidUFhdW5vZldrYURKeHVrQ0ZlQngiLCJpYXQiOjE0
                  NDk2MjQwMjYsImV4cCI6MTQ0OTYyNzYyNiwiYW1yIjpbInB3ZCJdLCJqdGkiOiI0ZUFXSk9DTUIzU1g4WGV3RGZWUiIsImF1dGh
                  fdGltZSI6MTQ0OTYyNDAyNiwiYXRfaGFzaCI6ImNwcUtmZFFBNWVIODkxRmY1b0pyX1EifQ.Btw6bUbZhRa89DsBb8KmL9rfhku
                  --_mbNC2pgC8yu8obJnwO12nFBepui9KzbpJhGM91PqJwi_AylE6rp-ehamfnUAO4JL14PkemF45Pn3u_6KKwxJnxcWxLvMuuis
                  nvIs7NScKpOAab6ayZU0VL8W6XAijQmnYTtMWQfSuaaR8rYOaWHrffh3OypvDdrQuYacbkT0csxdrayXfBG3UF5-ZAlhfch1fhF
                  T3yZFdWwzkSDc0BGygfiFyNhCezfyT454wbciSZgrA9ROeHkfPCaX7KCFO8GgQEkGRoQntFBNjluFhNLJIUkEFovEDlfuB4tv_M
                  8BM75celdy3jkpOurg"
}
~~~

#### Response Example (Error)

~~~http
HTTP/1.1 401 Unauthorized
Content-Type: application/json;charset=UTF-8
{
    "error" : "invalid_client",
    "error_description" : "No client credentials found."
}
~~~

### Introspection Request
{:.api .api-operation}

<span class="api-uri-template api-uri-get"><span class="api-label">POST</span> /oauth2/v1/introspect</span>

The API takes an Access Token, Refresh Token, or [ID Token](oidc.html#id-token) and returns whether it is active or not. 
If the token is active, additional data about the token is also returned. If the token is invalid, expired, or revoked, it is considered inactive. 
An implicit client can only introspect its own tokens, while a confidential client may inspect all access tokens.

#### Request Parameters

The following parameters can be posted as a part of the URL-encoded form values to the API.

Parameter       | Description                                                                                         | Type       |
----------------+-----------------------------------------------------------------------------------------------------+------------|
token           | An access token or refresh token.                                                                   | String     |  
token_type_hint | A hint of the type of *token*.                                                               | String     |
client_id       | The client ID generated as a part of client registration. This is used in conjunction with the *client_secret* parameter to authenticate the client application. | String |
client_secret   | The client secret generated as a part of client registration. This is used in conjunction with the *client_id* parameter to authenticate the client application. | String |

##### Token Authentication Methods

The client can authenticate by providing *client_id* and *client_secret* as a part of the URL-encoded form parameters (as described in table above),
or it can use basic authentication by providing the *client_id* and *client_secret* as an Authorization header using the Basic auth scheme.
Use one authentication mechanism with a given request. Using both returns an error.

For authentication with Basic auth, an HTTP header with the following format must be provided with the POST request.

~~~sh
Authorization: Basic ${Base64(<client_id>:<client_secret>)} 
~~~

#### Response Parameters

Based on the type of token and whether it is active or not, the returned JSON contains a different set of tokens. These are the possible values:

Parameter   | Description                                                                                         | Type       |
------------+-----------------------------------------------------------------------------------------------------+------------|
active      | An access token or refresh token.                                                                   | boolean    |  
token_type  | The type of the token, either *access_token*, *refresh_token*, or *id_token*.  | String     |
scope       | A space-delimited list of scopes.                                                                   | String     |
client_id   | The ID of the client associated with the token.                                                     | String     |
username    | The username associated with the token.                                                             | String     |
exp         | The expiration time of the token in seconds since January 1, 1970 UTC.                              | long       |
iat         | The issuing time of the token in seconds since January 1, 1970 UTC.                                 | long       |
nbf         | A timestamp in seconds since January 1, 1970 UTC when this token is not be used before.             | long       |
sub         | The subject of the token.                                                                           | String     |
aud         | The audience of the token.                                                                          | String     |
iss         | The issuer of the token.                                                                            | String     |
jti         | The identifier of the token.                                                                        | String     |
device_id   | The ID of the device associated with the token                                                      | String     |

#### List of Errors 

Error Id                |  Details                                                                                                     |
------------------------+--------------------------------------------------------------------------------------------------------------|
invalid_client          | The specified client id wasn't found. |
invalid_request         | The request structure was invalid. E.g. the basic authentication header was malformed, or both header and form parameters were used for authentication or no authentication information was provided. |

#### Response Example (Success, Access Token)

~~~json
{
    "active" : true,
    "token_type" : "access_token",
    "scope" : "openid profile",
    "client_id" : "a9VpZDRCeFh3Nkk2VdYa",
    "username" : "john.doe@example.com",
    "exp" : 1451606400,
    "iat" : 1451602800,
    "sub" : "00uid4BxXw6I6TV4m0g3",
    "aud" : "ciSZgrA9ROeHkfPCaXsa",
    "iss" : "https://your-org.okta.com",
    "jti" : "4eAWJOCMB3SX8XewDfVR"
}
~~~

#### Response Example (Success, Refresh Token)

~~~json
{
    "active" : true,
    "token_type" : "refresh token",
    "scope" : "openid profile email",
    "client_id" : "a9VpZDRCeFh3Nkk2VdYa",
    "username" : "john.doe@example.com",
    "exp" : 1451606400,
    "sub" : "00uid4BxXw6I6TV4m0g3",
    "device_id" : "q4SZgrA9sOeHkfst5uaa"
}
~~~

#### Response Example (Success, Inactive Token)

~~~json
{
    "active" : false
}
~~~

#### Response Example (Error)

~~~http
HTTP/1.1 401 Unauthorized
Content-Type: application/json;charset=UTF-8
{
    "error" : "invalid_client",
    "error_description" : "No client credentials found."
}
~~~

### Revocation Request
{:.api .api-operation}

<span class="api-uri-template api-uri-get"><span class="api-label">POST</span> /oauth2/v1/revoke</span>

The API takes an Access Token or Refresh Token and revokes it. Revoked tokens are considered inactive at the introspection endpoint. A client may only revoke its own tokens.

> Note: No errors occur if you use this endpoint, but it isn’t useful until custom scopes or resource servers are available. We recommend you wait until custom scopes and resource servers are available.

#### Request Parameters

The following parameters can be posted as a part of the URL-encoded form values to the API.

Parameter       | Description                                                                                         | Type       |
----------------+-----------------------------------------------------------------------------------------------------+------------|
token           | An access token or refresh token.                                                                   | String     |  
token_type_hint | A hint of the type of *token*.                                                               | String     |
client_id       | The client ID generated as a part of client registration. This is used in conjunction with the *client_secret* parameter to authenticate the client application. | String |
client_secret   | The client secret generated as a part of client registration. This is used in conjunction with the *client_id* parameter to authenticate the client application. | String |

##### Token Authentication Methods

A client may only revoke a token generated for that client.

The client can authenticate by providing *client_id* and *client_secret* as a part of the URL-encoded form parameters (as described in table above),
or it can use basic authentication by providing the *client_id* and *client_secret* as an Authorization header using the Basic auth scheme.
Use one authentication mechanism with a given request. Using both returns an error.

For authentication with Basic auth, an HTTP header with the following format must be provided with the POST request.

~~~sh
Authorization: Basic ${Base64(<client_id>:<client_secret>)} 
~~~

#### Response Parameters

A successful revocation is denoted by an empty response with an HTTP 200. Note that revoking an invalid, expired, or revoked token will still be considered a success as to not leak information

#### List of Errors 

Error Id                |  Details                                                                                                     |
------------------------+--------------------------------------------------------------------------------------------------------------|
invalid_client          | The specified client id wasn't found. |
invalid_request         | The request structure was invalid. E.g. the basic authentication header was malformed, or both header and form parameters were used for authentication or no authentication information was provided. |

#### Response Example (Success)

~~~http
HTTP/1.1 204 No Content
~~~

#### Response Example (Error)

~~~http
HTTP/1.1 401 Unauthorized
Content-Type: application/json;charset=UTF-8
{
    "error" : "invalid_client",
    "error_description" : "No client credentials found."
}
~~~
