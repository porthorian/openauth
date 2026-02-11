# REST Auth Example

Run:

```bash
go run ./examples/rest-auth
```

Request:

```bash
curl -sS -X POST http://localhost:8080/auth \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"user-123","token":"user-supplied-proof"}'
```

The response includes a JWT in `access_token`.

In this example, `client.AuthToken` returns identity context (`Principal`) and the handler issues the JWT after successful authentication.
