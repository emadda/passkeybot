import _ from "lodash";
import {verifyAuthenticationResponse} from "@simplewebauthn/server";

// This file shows an example of how to re-verify the passkeybot.com passkey and email API data.
// - The checks are all done server side on passkeybot.com so are not strictly needed, but allow you to reduce trust in passkeybot.com by double-checking the logic.


const to_sha256_uint8ar = (bytes_or_string): Uint8Array => {
	// SHA-256 = 32 bytes
	const sha256_uint8 = new Uint8Array(32);
	Bun.SHA256.hash(bytes_or_string, sha256_uint8);
	return sha256_uint8
};


// passkeys use base64 url format.
const to_b64url = (input) => {
	// input: string | Uint8Array | ArrayBuffer
	const s = input
	let b
	if (typeof s === 'string') b = Buffer.from(s, 'utf8')
	else if (s instanceof ArrayBuffer) b = Buffer.from(new Uint8Array(s))
	else if (s instanceof Uint8Array) b = Buffer.from(s)
	else throw new TypeError('input must be string | Uint8Array | ArrayBuffer')
	return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const from_b64url = (input, ret_uint8 = false) => {
	let s = String(input).replace(/-/g, '+').replace(/_/g, '/')
	const m = s.length % 4
	if (m) s += '='.repeat(4 - m) // pad to multiple of 4
	const b = Buffer.from(s, 'base64')
	return ret_uint8 ? new Uint8Array(b) : b.toString('utf8')
}

const from_b64url_to_uint8 = (x) => {
	return from_b64url(x, true)
}

const from_uint8_to_utf8_str = (uint8) => {
	return new TextDecoder('utf-8').decode(uint8)
}


/**
 * @param {object} api_res
 * @param {object} opts
 */
const re_verify_passkey_auth = async (api_res, opts) => {

	// Assert: API response is successful, verify meta data was requested.
	const is_verify_set = (
		_.isPlainObject(api_res) &&
		api_res?.ok === true &&
		_.isPlainObject(api_res?.data?.verify?.verify_input) &&
		_.isString(api_res?.data?.verify?.signed_msg_str) && api_res?.data?.verify?.signed_msg_str.length > 0
	)
	if (!is_verify_set) {
		return {
			ok: false,
			error_msg: `Verify not set. API response error, or verify was not requested`
		}
	}


	// The passkey `challenge` used in the options is the sha256(json_string).
	const signed_msg_str = api_res?.data?.verify?.signed_msg_str
	const sha256_uint8 = to_sha256_uint8ar(signed_msg_str);
	// const sha256_hex = sha256_uint8.toHex()
	const expected_challenge = to_b64url(sha256_uint8)

	// Assert: Options are correct.
	const is_opts_valid = (
		_.isPlainObject(opts?.expected) &&
		// _.isString(opts?.expected?.challenge) && opts?.expected?.challenge.length > 0 &&
		_.isString(opts?.expected?.origin) && opts?.expected?.origin.length > 0 &&
		_.isString(opts?.expected?.rpid) && opts?.expected?.rpid.length > 0 &&
		_.isString(expected_challenge) && expected_challenge.length > 0 &&
		// PKCE (code_verifier, code_challenge) pair. This comes from the users cookie session (not user input), so has been verified to be for the correct session.
		_.isString(opts?.server_side_code_challenge_hex) && opts?.server_side_code_challenge_hex.length === 64
		// _.isString(opts?.expected?.op_type) && opts?.expected?.op_type.length > 0
	)

	if (!is_opts_valid) {
		return {
			ok: false,
			error_msg: `Invalid options`,
			data: {
				opts
			}
		}
	}

	const old_verify = api_res?.data?.verify?.verify_input
	const old_verify_output = api_res?.data?.verify?.verify_output
	const new_verify = _.cloneDeep(old_verify)
	new_verify.expectedChallenge = expected_challenge; // b64url
	new_verify.expectedOrigin = [opts.expected.origin];
	new_verify.expectedRPID = opts.expected.rpid;

	// Use the same type. Will be one of: (webauthn.get, webauthn.create)
	new_verify.expectedType = old_verify.expectedType

	const cred_pub_key_uint8 = from_b64url_to_uint8(new_verify.credential.publicKey)
	new_verify.credential.publicKey = cred_pub_key_uint8

	let verify_output
	try {
		verify_output = await verifyAuthenticationResponse(new_verify)
	} catch (e) {
		return {
			ok: false,
			error_msg: e?.message ?? `Unknown error message (verifyAuthenticationResponse)`,
			data: {
				error: e
			}
		}
	}

	const is_new_verify_output_ok = (
		verify_output?.verified
		// _.isEqual(verify_output, old_verify_output) // Matches what passkeybot.com computed server side (be careful of schema changes for different simplewebauthn versions).
	)

	if (!is_new_verify_output_ok) {
		return {
			ok: false,
			error_msg: `verify_output.verified is false`,
			data: {
				new_verify,
				verify_output
			}
		}
	}

	// Everything in this JSON is integrity protected by the passkey auth.
	let signed_json
	try {
		signed_json = JSON.parse(signed_msg_str)
	} catch (e) {
		return {ok: false, error_msg: `Invalid JSON`}
	}


	if (signed_json?.code_challenge !== opts.server_side_code_challenge_hex) {
		return {
			ok: false,
			error_msg: `PKCE code_challenge does not match`,
			data: {
				signed_json,
				opts
			}
		}
	}

	// Assert: Data in the top level API response matches those from the verified passkey auth.
	const si = api_res?.data?.sign_in
	const signed_data_matches_api_data = (
		_.isPlainObject(si) &&
		si?.passkey_id === `passkey_${to_sha256_uint8ar(cred_pub_key_uint8).toHex()}` &&
		_.isString(si?.cred_id_b64) && si.cred_id_b64 === new_verify?.credential?.id &&
		_.isString(si?.cred_pub_key_b64) && si.cred_pub_key_b64 === old_verify?.credential?.publicKey &&
		// _.isString(si?.passkey_uid) && si.passkey_uid === new_verify?.response?.response?.userHandle && // userHandle is optional, may change in the future.
		_.isString(si?.domain) && si.domain === opts.expected.rpid
	)
	if (!signed_data_matches_api_data) {
		return {
			ok: false,
			error_msg: `Data from the API response do not match those from the passkey auth`,
		}
	}


	return {
		ok: true,
		data: {
			signed_json
		}
	}
}


/**
 * Optional but recommended.
 * - Passkeybot already does these checks server side, but you can re-verify to be certain.
 *
 * Assert: Email hash is correct.
 * Assert: Email `from` is correct.
 * Assert: DKIM and DMARC checks pass.
 *
 * @param {object} api_res
 * @param {object} signed_json JSON object from api_res.verify.signed_msg_str that has been parsed and verified (the passkey auth signed it).
 */
const re_verify_email = async (api_res, signed_json) => {
	const is_signed_json_valid = (
		_.isPlainObject(signed_json) &&
		_.isString(signed_json?.email) &&
		_.isString(signed_json?.email_id) &&
		_.isString(signed_json?.email_bytes_sha256_hex)
	)
	if (!is_signed_json_valid) {
		return {
			ok: false,
			error_msg: `Email metadata not included in signed_json`,
		}
	}

	// Note: Only set on the first use of the passkey (when the user has verified their email in the passkey creation flow).
	const si = api_res?.data?.sign_in
	const er = api_res?.data?.email_received
	const is_er_set = (
		_.isPlainObject(si) &&
		_.isPlainObject(er) &&
		_.isString(er?.email_bytes_sha256_hex) &&
		_.isString(er?.email_bytes_b64) &&
		signed_json.email_bytes_sha256_hex === er.email_bytes_sha256_hex &&
		si?.email_id === signed_json?.email_id
	)
	if (!is_er_set) {
		return {
			ok: false,
			error_msg: `email_received is not set. It is only set on the first passkey usage`,
		}
	}


	// .eml format email with headers
	const email_bytes = from_b64url_to_uint8(er.email_bytes_b64)
	const new_email_sha256 = to_sha256_uint8ar(email_bytes).toHex()
	const email_str = from_uint8_to_utf8_str(email_bytes)

	// Recheck the hash is correct.
	if (!(
		new_email_sha256 === signed_json.email_bytes_sha256_hex &&
		new_email_sha256 === er.email_bytes_sha256_hex
	)) {
		return {
			ok: false,
			error_msg: `Email content sha256 did not match what was expected`,
		}
	}


	// Note: Passkeybot already does this server side.
	// @todo:
	// - 1. Verify the DKIM/DMARC headers on email_str pass.
	// - 2. Verify the From: matches `signed_json.email` exactly.
	// - 3. Verify the email body contains the passkey_id (without the `passkey_` prefix, hex chars only).
	// 		- api_res.data.sign_in.passkey_id = "passkey_" + to_sha256_uint8ar(cred_pub_key_uint8).toHex()


	return {
		ok: true
	}
}

/**
 * Optional but recommended.
 * Passkeybot already performs these checks server-side; this helper lets you re-verify client-side.
 *
 * Checks:
 * - On first passkey usage:
 *   - Passkey auth is authentic, and signed data contains the email hash.
 *   - Email "From" is authentic, and email body contains the passkey public key.
 * - On subsequent passkey usages:
 *   - (passkey_id, email_id, user_id) is a valid combination (previously verified).
 *
 * @param {object} opts
 * @param {object} opts.api_res API response from passkeybot.com
 * @param {string} opts.pkce_code_challenge_hex PKCE code challenge (hex)
 * @param {string} opts.origin Origin running the JS passkey APIs (e.g. "https://passkeybot.com")
 * @param {string} opts.rpid Relying Party ID (domain only, no protocol; e.g. "your_domain.com")
 * @returns {{ ok: boolean, [k: string]: any }}
 */
export const re_verify_passkey_and_email = async (opts) => {
	const {
		api_res,
		pkce_code_challenge_hex,
		origin,
		rpid
	} = opts

	const si = api_res?.data?.sign_in

	const re_verify = await re_verify_passkey_auth(
		api_res,
		{
			server_side_code_challenge_hex: pkce_code_challenge_hex,
			expected: {origin, rpid}
		}
	)

	if (!re_verify.ok) {
		return re_verify
	}

	// Note: Instead of trusting `is_first_use_of_passkey`, you can also check your DB to see if the (user_id, email_id, passkey_id) combo has been seen before.
	if (si?.is_first_use_of_passkey) {
		const ve_em = await re_verify_email(api_res, re_verify.data.signed_json)
		if (!ve_em.ok) {
			return ve_em
		}

		// @todo
		// Example SQL database schema. You will need something similar.
		// CREATE TABLE verified_passkeys (passkey_id TEXT NOT NULL, email_id TEXT NOT NULL, email TEXT NOT NULL, user_id TEXT NOT NULL, verified_ts INTEGER NOT NULL DEFAULT (unixepoch()));
		// CREATE UNIQUE INDEX vp_unique_index_01 ON verified_passkeys (passkey_id, email_id, user_id);

		// @todo
		// Record that the (passkey, email) combination have been verified.
		// INSERT INTO verified_passkeys (passkey_id, email_id, user_id) VALUES (si?.passkey_id, si?.email_id, si?.user_id);
	} else {

		// When the passkey is used again, only ever let it be used in combination with the same (passkey_id, email_id, user_id).
		// - The (passkey, email) combination has been verified, user_id is trusted from passkeybot (you can enforce one user_id has a max of one email_id to remove trust in passkeybot and avoid allowing one user_id having many emails. The API schema allows this to enable one user_id account having many emails in the future, but is not currently used).
		//
		// - SQL relations:
		// - Each passkey belongs to one email. Each email belongs to one user_id.
		// - A user_id can have many emails. An email can have many passkeys.

		// @todo
		// const row_found = SELECT * FROM verified_passkeys WHERE passkey_id = si?.passkey_id AND email_id = si?.email_id AND user_id = si?.user_id LIMIT 1
		const row_found = true
		if (!row_found) {
			return {
				ok: false,
				error_msg: `(passkey_id, email_id, user_id) combination did not match the ones observed on initial (passkey, email) verification`
			}
		}
	}

	// When: Verification ok.
	return {
		ok: true
	}
}
