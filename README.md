# apply-auth
**jwt-authorization**

```golang

//init with secret
auth.Init("my-secret")

//add routes for public access
auth.AllowAnonymous("/public", "GET")

//http handler
auth.JWT

```