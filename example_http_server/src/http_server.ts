import * as _ from "lodash"
import config from "./../config.json"
import type {CookieMap} from "bun";
import {session} from "./session.ts";
import type {ResultGetSignInOnceResponse} from "../../api_schema/sign_in.ts";
import {re_verify_passkey_and_email} from "./re_verify.ts";


const your_domain = config?.your_domain ?? null
const sign_in_url = `https://passkeybot.com/${your_domain}`
const https_pkb = `https://passkeybot.com`

if (!_.isString(your_domain)) {
	throw new Error(`Set "your_domain" in the config.json file`);
}


const http_post_json = async (url, body) => {
	try {
		const r = await fetch(url, {
			method: "POST",
			headers: {"Content-Type": "application/json"},
			body: JSON.stringify(body),
		});
		return await r.json();
	} catch (e) {
		console.error("fetch.error", e)
		return null
	}
};

const json_res = (x) => Response.json(x)

const new_pkce_pair = async () => {
	const v = new Uint8Array(32);
	crypto.getRandomValues(v);
	const c = new Uint8Array(await crypto.subtle.digest("SHA-256", v));

	return {
		// Secret kept on the server side.
		code_verifier: v.toHex(),

		// sha256(code_verifier) sent to passkeybot.
		code_challenge: c.toHex()
	}
}

const timing_safe_equal_str = (a, b) => {
	const enc = "utf8"
	const x = Buffer.from(a, enc);
	const y = Buffer.from(b, enc);

	// timingSafeEqual throws if lengths differ
	if (x.length !== y.length) return false;

	return crypto.timingSafeEqual(x, y);
};


const port = 7777
const server = Bun.serve({
	port,
	routes: {
		"/*": () => {
			const h = new Headers();
			h.set("Location", "/user_account");

			return new Response(null, {
				status: 303,
				headers: h
			});
		},

		"/.well-known/webauthn": {
			GET: async (req) => {
				return json_res({"origins": ["https://passkeybot.com"]})
			}
		},

		"/passkey/redirect_to_sign_in": {
			GET: async (req) => {
				const h = new Headers();

				const pair = await new_pkce_pair();

				const s = session.create_new()
				s.data.pkce_pair = pair

				// Add `Set-Cookie` header to the response.
				// Note: SameSite must be `Lax` so that the cookies are correctly set when redirecting from one domain to another.
				session.set_set_cookie_header(req, s)


				// Redirect to passkeybot.com/your_domain.com
				h.set("Location", `${sign_in_url}?code_challenge=${pair.code_challenge}`);

				return new Response(null, {
					status: 303,
					headers: h
				});
			}
		},


		"/passkey/start_session": {
			GET: async (req) => {


				// No Iframes.
				const he = req.headers;
				const ok = (
					he.get("sec-fetch-mode") === "navigate" &&  // Triggered by browser navigation.
					he.get("sec-fetch-dest") === "document" // Response is used as a document in the browser
				);

				if (!ok) {
					return new Response(`Correct request headers are not set. Ensure the "post from" domain is allowed.`);
				}

				const sp = Object.fromEntries((new URL(req.url)).searchParams.entries());

				const params_ok = (
					_.isString(sp?.sign_in_id) &&
					sp?.sign_in_id.length >= 32 &&
					_.isString(sp?.code_challenge) &&
					sp?.code_challenge.length === 64
				);
				if (!params_ok) {
					return new Response(`URL params are not valid. Set a sign_in_id and code_challenge.`);
				}

				const {
					sign_in_id: user_input_sign_in_id,
					code_challenge: user_input_code_challenge
				} = sp;

				const s = session.get_existing(req)
				if (!s) {
					return new Response(`No session found for the provided cookie. The session is needed to retrieve the connected pkce.code_verifier secret.`);
				}

				const pair = s.data?.pkce_pair ?? null
				if (!pair) {
					return new Response(`PKCE pair not set on the session`);
				}


				// IMPORTANT:
				// Prevent CSRF. PKCE pair (code_verifier, code_challenge) must be used on the same session that created it.
				// - This prevents an attacker using their sign_in_id on another browser, or stealing a sign_in_id for use on the attacker's browser (because the attacker does not have the correct session_id that is set in the cookie).
				const challenge_ok = (
					_.isString(pair?.code_challenge) &&
					pair?.code_challenge.length === 64 &&
					timing_safe_equal_str(pair.code_challenge, user_input_code_challenge)
				)
				if (!challenge_ok) {
					return new Response(`PKCE code_challenge from the session does not match the one provided via the URL params`);
				}

				const code_verifier_hex = pair?.code_verifier

				const post_body = {
					sign_in_id: user_input_sign_in_id,
					code_verifier_hex,
					include: "verify",
				}

				const res: ResultGetSignInOnceResponse = await http_post_json(`https://api.passkeybot.com/api/v1/get_sign_in_once`, post_body);

				// IMPORTANT:
				const sign_in_is_successful = (
					_.isPlainObject(res) &&
					res?.ok &&
					res?.data?.sign_in
				)

				if (!sign_in_is_successful) {
					console.error("fetch.error", res)
					return new Response(`sign_in expired or other error`)
				}


				// `res.ok === true` means Sign in is valid / successfully verified.
				// - Any network error, any http error, or res.ok === false means that the auth flow failed / has already been used once / has expired.

				// IMPORTANT:
				// Check the RP domain of the passkey is for this domain.
				if (res.data.sign_in.domain !== config.your_domain) {
					return new Response(`RP domain is not correct`)
				}

				// IMPORTANT:
				if (res?.data?.verify?.signed_msg?.code_challenge !== pair.code_challenge) {
					return new Response(`PKCE code_challenge from session does not match the one in the passkey signed_msg`)
				}

				// Optional but recommended.
				const v = await re_verify_passkey_and_email({
					api_res: res,
					pkce_code_challenge_hex: pair.code_challenge,
					origin: https_pkb,
					rpid: config.your_domain
				})
				if (!v.ok) {
					console.log("re_verify.failed");
					return new Response(`re_verify failed ${v.error_msg}`, {status: 422})
				}
				console.log("re_verify.successful");


				console.log("fetched.sign_in", {res})

				// IMPORTANT:
				// Create a new "signed in" session to avoid session fixation.
				// - "session fixation" = when the attacker has the user sign in into a session_id that is known ahead of time.
				// - Creating a new random session_id after sign-in avoids this.
				// - Copy any needed state to the new session.
				session.delete_session(s)
				const s2 = session.create_new()
				s2.data.is_signed_in = true
				s2.data.sign_in_id = res.data?.sign_in?.sign_in_id
				session.set_set_cookie_header(req, s2)


				// Redirect
				const h = new Headers();
				h.set("Location", "/user_account");

				return new Response(null, {
					status: 303,
					headers: h
				});

			},

		},

		"/user_account": {
			GET: async (req) => {
				const s = session.get_existing(req);
				let msg = `❌ You are not signed in.<br/><br/><a href="/passkey/redirect_to_sign_in">Sign In</a> <i>(Note: Use the Chrome Dev Tools WebAuthn virtual authenticator for fast passkey creation)</i>`

				// Will be true after a previous Passkeybot sign in.
				if (s?.data?.is_signed_in) {
					msg = `✅ You are signed in.<br/>Your cookie session_id is ${s.session_id}.<br/><br/><a href="/sign_out">Sign Out (delete session)</a>.`
				}
				return new Response(msg, {headers: {"content-type": "text/html; charset=utf-8"}})
			}
		},

		"/sign_out": {
			GET: async (req) => {
				session.delete_session_if_exists(req)
				const h = new Headers();
				h.set("Location", "/user_account");

				return new Response(null, {
					status: 303,
					headers: h
				});
			}
		},

	}
})

console.log(`• Local server running:\n\t→ http://localhost:${port}\n`)
console.log(`• HTTPS reverse proxy running:\n\t→ https://${config.your_domain}\n`)
console.log(`• User account page\n\t→ https://${config.your_domain}/user_account\n`);
console.log(``)
console.log(`Note: cmd-click links to open.`)
console.log(`Note: It is normal for Chrome to show a warning for the newly created HTTPS domain on {x}.trycloudflare.com.`)


