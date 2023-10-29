# Protecting Camp

- Run `snyk code test` to find vulnerabilities.
- Found 1 high severity vulnerability: `SSRF on line 68 of index.js`
- Can exploit SSRF protection in ParseURL function by using `localhost` instead of `127.0.0.1`
- For `parse-url` lib: `https://www.npmjs.com/package/parse-url`
- `resource == domain`

From Snyk CLI:

```bash
 ✗ [High] Server-Side Request Forgery (SSRF) 
   Path: index.js, line 68 
   Info: Unsanitized input from the HTTP request body flows into request, where it is used as an URL to perform a request. This may result in a Server-Side Request Forgery vulnerability.
```

- From `PayloadAllTheThings`: can get around the `127.0.0.1` check in `ParseURL` library using `<targetdomain>:<targetport>@@127.0.0.1:3000`. [Look Here For More Detail](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypass-against-a-weak-parser)
- Exploit code in [protectingcamp.py](protectingcamp.py)

## Flag

1. Flag: `flag{d716dd8ab70bbc51a5f1d0182c84bcc8}`

