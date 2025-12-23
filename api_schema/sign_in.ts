export type ResultGetSignInOnceResponse =
	| { ok: true; data: GetSignInOnceResponse }
	| { ok: false; error_msg: string }

/**
 * Response from:
 * POST https://api.passkeybot.com/api/v1/get_sign_in_once
 */
export type GetSignInOnceResponse = {
	/** Always present. All keys inside are required/always set. */
	sign_in: SignIn

	/**
	 * Present only if POST body included `include: "verify"`.
	 * Can be null.
	 */
	verify: Verify | null

	/**
	 * Present only if POST body included `include: "verify"`.
	 * Can be null.
	 */
	email_received: EmailReceived | null
}

/**
 * Passkeybot sign-in event.
 * All keys are required/always set.
 */
export type SignIn = {
	/** Indicates whether this is the first time this specific passkey has been used. */
	is_first_use_of_passkey: boolean

	/** Passkeybot ID for this sign-in event. */
	sign_in_id: string

	/**
	 * RP (Relying Party / Requesting Party) domain of the passkey.
	 * Should match your domain in your handler.
	 * - Will be identical to `verify_output.authenticationInfo.rpID` (when `verify` is included).
	 */
	domain: string

	/**
	 * Passkeybot user ID.
	 * Treat as the stable reference to a given user account.
	 */
	user_id: string

	/**
	 * Passkeybot ID for the passkey used.
	 * - Equals `cred_pub_key_bytes.to_sha256().to_hex()`
	 */
	passkey_id: string

	/** JS credential ID (base64url). */
	cred_id_b64: string

	/** JS credential public key (base64url). */
	cred_pub_key_b64: string

	/**
	 * Name shown in the passkey chooser client-side.
	 * Trailing number is the passkey counter number for users with multiple passkeys on same email.
	 */
	passkey_name: string

	/**
	 * Display name shown in client-side UI.
	 * For logic, use `domain` instead (this can be changed and is only a UI label).
	 */
	passkey_rp_name: string

	/**
	 * JS randomly generated "user_id" assigned to this passkey (WebAuthn API convention).
	 * Not currently used; may be used in future for replacing/deleting keys from JS.
	 */
	passkey_uid: string

	/**
	 * Passkeybot ID for the email.
	 * Every email gets a unique ID to show normalization mapping.
	 */
	email_id: string

	/** Normalized email address used for the passkey. */
	email: string

	/**
	 * Timestamp of sign-in.
	 * You do not need to enforce a time limit: API will not return previously used or expired `sign_in_id`.
	 */
	ts: string // ISO 8601
}

/**
 * Verification details (Passkeybot already verifies and only returns `sign_in` if it succeeds).
 * Included only when POST body includes `include: "verify"`.
 */
export type Verify = {
	/**
	 * Pass this object to `@simplewebauthn/server`:
	 * `verifyAuthenticationResponse(verify_input)`
	 */
	verify_input: VerifyInput

	/**
	 * Output returned from `@simplewebauthn/server` verify call.
	 * `verified` is expected to be true when present.
	 */
	verify_output: VerifyOutput

	/** Parsed version of `signed_msg_str` for easy access. */
	signed_msg: SignedMsg

	/**
	 * Exact string of bytes that was hashed (sha256) to form the `challenge`.
	 * Exact bytes matter, hence string not parsed JSON.
	 */
	signed_msg_str: string
}

/** Input object for `@simplewebauthn/server` verifyAuthenticationResponse(...) */
export type VerifyInput = {
	/** WebAuthn authentication credential response payload. */
	response: AuthenticationCredential

	/** Challenge expected by the server. */
	expectedChallenge: string

	/** Expected origin(s) for the WebAuthn response. */
	expectedOrigin: string[]

	/** Expected RP ID (Relying Party ID). */
	expectedRPID: string

	/** Expected WebAuthn ceremony type. */
	expectedType: string

	/** Stored credential material + counter. */
	credential: {
		/** Credential ID (base64url). */
		id: string
		/** Credential public key (base64url). */
		publicKey: string
		/** Stored signature counter. */
		counter: number
	}
}

/** WebAuthn "public-key" credential returned by the browser. */
export type AuthenticationCredential = {
	/** Credential ID (base64url). */
	id: string
	/** Raw credential ID (base64url). */
	rawId: string
	/** Typically "public-key". */
	type: string

	/** Authenticator response payload. */
	response: {
		/** Base64url-encoded authenticator data. */
		authenticatorData: string
		/** Base64url-encoded client data JSON. */
		clientDataJSON: string
		/** Base64url-encoded signature. */
		signature: string
		/** Base64url-encoded user handle. */
		userHandle: string
	}

	/** Attachment modality, e.g. "platform". */
	authenticatorAttachment: string

	/** Client extension outputs (varies by browser/extensions). */
	clientExtensionResults: Record<string, unknown>
}

/** Output returned from `@simplewebauthn/server` verification. */
export type VerifyOutput = {
	/** Whether the authentication response verified successfully. */
	verified: boolean

	/** Authentication info produced on success. */
	authenticationInfo: {
		/** Updated signature counter after verification. */
		newCounter: number
		/** Credential ID (base64url). */
		credentialID: string
		/** Whether user verification (UV) was performed. */
		userVerified: boolean
		/** Device type classification, e.g. "singleDevice". */
		credentialDeviceType: string
		/** Whether the credential is backed up / synced. */
		credentialBackedUp: boolean
		/** Origin used in the response, e.g. "https://passkeybot.com". */
		origin: string
		/** RP ID used for verification. Copied to `sign_in.domain`. */
		rpID: string
	}
}

/** Parsed message used to derive/validate the WebAuthn challenge. */
export type SignedMsg = {
	/** SHA256 hex of PKCE code challenge (or similar). */
	code_challenge: string
	/** Activation code as hex. */
	activation_code_hex: string
	/** Email address used. */
	email: string
	/** Passkeybot email ID. */
	email_id: string
	/** sha256 hex hash of the email content (used in signing). */
	email_bytes_sha256_hex: string
	/** Timestamp for the signed message. */
	ts: string // ISO 8601
	/** At least 256 bits of randomness included in the challenge. */
	random_bytes_hex: string
}

/**
 * Email payload returned only when `include: "verify"` is used.
 * (Email included for the first sign-in event for that email when it is new.)
 */
export type EmailReceived = {
	/** sha256 hex hash of the email content (used in signing). */
	email_bytes_sha256_hex: string

	/**
	 * Exact plain text email in .eml format (base64).
	 * Use to verify email was sent from correct address and not spoofed.
	 */
	email_bytes_b64: string

	/** Timestamp when the email was received. */
	email_received_ts: string // ISO 8601
}
