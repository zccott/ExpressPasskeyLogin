import type { Base64URLString } from '../deps.js';
/**
 * Decode an authenticator's base64url-encoded clientDataJSON to JSON
 */
export declare function decodeClientDataJSON(data: Base64URLString): ClientDataJSON;
export type ClientDataJSON = {
    type: string;
    challenge: string;
    origin: string;
    crossOrigin?: boolean;
    tokenBinding?: {
        id?: string;
        status: 'present' | 'supported' | 'not-supported';
    };
};
export declare const _decodeClientDataJSONInternals: {
    stubThis: (value: ClientDataJSON) => ClientDataJSON;
};
