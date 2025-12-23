# Passkeybot.com HTTP server example

These are example HTTP handlers you need to implement on your server to handle Passkeybot authentication.

You can use them directly, or you can ask your LLM to rewrite them for your own language/framework.


## Running

- `git clone https://github.com/emadda/passkeybot`
- `cd passkeybot/example_http_server`

- Install deps:
	- [cloudflared](https://github.com/cloudflare/cloudflared)
	- [bun web server](https://bun.com/docs/installation)
	- NPM deps
		- Run `bun i`
		

- Running
	- `chmod +x ./sh/*`
	- Terminal 1
		- `./sh/step_1_start_https_rev_proxy.sh`
			- Creates a free random HTTPS domain, reverse proxies it locally to localhost:7777
	- Terminal 2
		- `./sh/step_2_start_local_http_server.sh`
			- Runs the webserver at localhost:7777

    - `sessions.json` can be observed in your text editor so you can see the state transitions as you use the demo. 