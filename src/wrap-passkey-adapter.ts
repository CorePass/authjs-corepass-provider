import type { Adapter } from "@auth/core/adapters"
import { CredentialsSignin } from "@auth/core/errors"

/**
 * Error code set in redirect URL when authenticator/user is not found (CredentialsSignin.code).
 * Generic name so apps and other providers can reuse it. Use with error=CredentialsSignin.
 */
export const CREDENTIALS_SIGNIN_CODE_USER_NOT_FOUND = "UserNotFound"

/**
 * Wraps an Auth.js adapter so that when getAuthenticator returns null (passkey not in DB),
 * throws CredentialsSignin with code {@link CREDENTIALS_SIGNIN_CODE_USER_NOT_FOUND} instead of
 * letting Auth.js throw a generic AuthError (which is surfaced as error=Configuration).
 * Use this when passing the adapter to SvelteKitAuth so the client receives
 * error=CredentialsSignin&code=UserNotFound and can show a "not found" message.
 */
export function wrapPasskeyAdapter<T extends Adapter>(adapter: T): T {
	if (!adapter || typeof adapter !== "object") return adapter
	const getAuthenticator = adapter.getAuthenticator
	if (typeof getAuthenticator !== "function") return adapter
	return {
		...adapter,
		getAuthenticator: async (credentialID: Parameters<typeof getAuthenticator>[0]) => {
			const authenticator = await getAuthenticator.call(adapter, credentialID)
			if (authenticator == null) {
				const err = new CredentialsSignin("Authenticator not found in database.")
				;(err as { code?: string }).code = CREDENTIALS_SIGNIN_CODE_USER_NOT_FOUND
				throw err
			}
			return authenticator
		},
	} as T
}
