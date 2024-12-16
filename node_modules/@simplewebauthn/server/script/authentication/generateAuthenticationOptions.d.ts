import type { AuthenticationExtensionsClientInputs, AuthenticatorTransportFuture, Base64URLString, PublicKeyCredentialRequestOptionsJSON, UserVerificationRequirement } from '../deps.js';
export type GenerateAuthenticationOptionsOpts = {
    rpID: string;
    allowCredentials?: {
        id: Base64URLString;
        transports?: AuthenticatorTransportFuture[];
    }[];
    challenge?: string | Uint8Array;
    timeout?: number;
    userVerification?: UserVerificationRequirement;
    extensions?: AuthenticationExtensionsClientInputs;
};
/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator authentication
 *
 * **Options:**
 *
 * @param rpID - Valid domain name (after `https://`)
 * @param allowCredentials **(Optional)** - Authenticators previously registered by the user, if any. If undefined the client will ask the user which credential they want to use
 * @param challenge **(Optional)** - Random value the authenticator needs to sign and pass back user for authentication. Defaults to generating a random value
 * @param timeout **(Optional)** - How long (in ms) the user can take to complete authentication. Defaults to `60000`
 * @param userVerification **(Optional)** - Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise set to `'preferred'` or `'required'` as desired. Defaults to `"preferred"`
 * @param extensions **(Optional)** - Additional plugins the authenticator or browser should use during authentication
 */
export declare function generateAuthenticationOptions(options: GenerateAuthenticationOptionsOpts): Promise<PublicKeyCredentialRequestOptionsJSON>;
