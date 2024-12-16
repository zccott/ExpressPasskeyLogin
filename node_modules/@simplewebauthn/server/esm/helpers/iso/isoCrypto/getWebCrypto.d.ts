import type { Crypto } from '../../../deps.js';
/**
 * Try to get an instance of the Crypto API from the current runtime. Should support Node,
 * as well as others, like Deno, that implement Web APIs.
 */
export declare function getWebCrypto(): Promise<Crypto>;
export declare class MissingWebCrypto extends Error {
    constructor();
}
export declare const _getWebCryptoInternals: {
    stubThisGlobalThisCrypto: () => globalThis.Crypto;
    setCachedCrypto: (newCrypto: Crypto | undefined) => void;
};
