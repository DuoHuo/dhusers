dhusers
=======

[![Greenkeeper badge](https://badges.greenkeeper.io/DuoHuo/dhusers.svg)](https://greenkeeper.io/)

DHUsers provides RESTful API for user management for DuoHuo Apps, using Node.js & MongoDB.

## APP Verification

* APIKey - All requests should contain apikey parameter, such as POST http://example.com/u/test?apikey=yourpaikeyhere
* IP whitelist (optional) only IPs in a array could invoke the API server. This can be edited in config.

## APIs

#### Register

Path: `/reg`

Method: POST

body:

  * `username` must be alphanumeric
  * `email` must be valid email
  * `password` better to be encrypted. Will be encrypted again using sha256.
  * `siteurl` the url the user shall be redirected to(such as http://app.example.com/login). Will displayed in email sent to user for activation or other stuff.

#### Login

Path: `/login`

Method: POST

body: 

  * `username` for login user
  * `password` for login credentials
  * `ipaddress` for security logs

#### Forgot password

Path: `/forgot-password`

Method: POST

body:

  * `email`: email address that resetkey will be sent to.
  * `siteurl`: url the user will be redirected to.
  * `ipaddress`: for security logs & emails.
    
#### Get user information

Path: `/u/[username]`

Method: GET

Params:

  * `username` username's information to get. E.g., GET http://example.com/u/testuser

#### Update user information

Path: `/u/[username]`

Method: POST

body:

  * `email` user's email (can be updated)
  * `password` user's password. **ATTENTION** DHUsers will NOT check the password, please ensure the current user has correct privilege to change the password, or just keep it unchanged. This variable can be old password or new password.

## Returning value

All return results will be in JSON format.

* `status`: `OK`|`ERROR`
* `message`: Additional message for result.
* `user`: User information in JSON format.

Example:

GET /u/test

And get:
```JSON
{
  "status": "OK",
  "message": "",
  "user": {
    "name": "test",
    "password": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "email": "test@test.com",
    "role": "user"
  }
}
```

## TODO

* Pages for account activation.
* Pages for password reset.
