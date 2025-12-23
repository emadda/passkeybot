import type {BunRequest, CookieInit} from "bun"

// Simple HTTP session storage mock.
// - Stores sessions in a JSON file in the same dir as this .ts file.
// - For demo purposes only.


import fs from "fs";
import path from "path";
import {fileURLToPath} from "url";

// resolve sessions.json in same dir as this .ts file
const f = fileURLToPath(import.meta.url);
const d = path.dirname(f);
const sessions_path = path.join(d, "sessions.json");
const sessions_tmp_path = sessions_path + ".tmp";

// Check if sessions.json exists
const sessions_file_exists_sync = () => {
	return fs.existsSync(sessions_path);
};

// Create sessions.json with { "sessions": {} } if it does not exist
const create_sessions_file_if_missing_sync = () => {
	if (!sessions_file_exists_sync()) {
		const j = JSON.stringify({sessions: {}}, null, 2);
		fs.writeFileSync(sessions_path, j, "utf8");
	}
};

// Get existing JSON, or create default and then return it
const get_or_create_sessions_json = () => {
	create_sessions_file_if_missing_sync();
	const t = fs.readFileSync(sessions_path, "utf8");
	return JSON.parse(t);
};

// Write full JSON atomically (to same file)
const write_sessions_sync = (o: any) => {
	const j = JSON.stringify(o, null, 2);
	fs.writeFileSync(sessions_tmp_path, j, "utf8");
	fs.renameSync(sessions_tmp_path, sessions_path);
};


// Any time JS writes to a session object write it to the JSON file.
// - This is for demo purposes only.
// - Allow live-reloading the server without removing current session state.
// - Allow easily observing the session data for demo purposes.
const write_session_changes_to_file_deep = (o: any) => {
	const wrap_deep = (t: any): any => {
		if (!t || typeof t !== "object") return t;

		for (const k of Object.keys(t)) {
			t[k] = wrap_deep(t[k]);
		}

		return new Proxy(t, {
			set(target, p, v) {
				const v2 = wrap_deep(v);
				// @ts-expect-error
				target[p] = v2;
				save_sessions_to_file();
				return true;
			},
			deleteProperty(target, p) {
				// @ts-expect-error
				delete target[p];
				save_sessions_to_file();
				return true;
			}
		});
	};

	return wrap_deep(o);
};


const sessions_json_file = get_or_create_sessions_json()
const save_sessions_to_file = () => {
	write_sessions_sync({
		...sessions_json_file,
		sessions
	})
}

export const sessions = write_session_changes_to_file_deep(sessions_json_file.sessions)
const session_key = "session_id"


const default_cookie_options: CookieInit = {
	// Needed to allow for setting the cookie after a cross-site <form> POST or GET redirect.
	sameSite: "lax",
	httpOnly: true,
	secure: true,
	path: "/",
	maxAge: 60 * 60 * 24 * 30, // 30 days
}


export const session = {
	create_new() {
		const o = {
			session_id: `${session_key}_${get_random_32_byte_hex()}`,
			data: {
				is_signed_in: false,
				created_ts: new Date().toISOString()
			}
		}

		// This wraps it in the proxy, which saves writes to the JSON file.
		sessions[o.session_id] = o

		// Return the proxied object (not the original `o`).
		return sessions[o.session_id]
	},

	// Set Set-Cookie header on the response to the given request.
	// - Will overwrite previous value.
	set_set_cookie_header(req: BunRequest, s) {
		req.cookies.set(session_key, s.session_id, default_cookie_options);
	},

	get_existing(req: BunRequest) {
		const session_id = req.cookies.get(session_key)
		if (session_id in sessions) {
			return sessions[session_id]
		}
		return null
	},

	// Delete session on server and remove the key.
	delete_session_if_exists(req: BunRequest) {
		const s = this.get_existing(req)
		if (s === null) {
			return
		}
		this.delete_session(s)
		req.cookies.set(session_key, "", {...default_cookie_options, maxAge: 0});
	},

	delete_session(s) {
		delete sessions[s.session_id]
	}

}


const get_random_32_byte_hex = () => {
	const b = new Uint8Array(32);
	crypto.getRandomValues(b);
	return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
};