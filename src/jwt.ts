import { PluginError } from "@t3tools/plugin-api";
import * as Effect from "effect/Effect";
import * as Jwk from "effect/jose/Jwk";
import * as Jws from "effect/jose/Jws";
import * as Jwt from "effect/jose/Jwt";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

export const normalizeIssuer = (value: string) => value.trim().replace(/\/+$/u, "");

const normalizePem = (value: string) => value.replace(/\\n/gu, "\n").trim();

export const KeyPair = Schema.Struct({ privateKey: Schema.String, publicKey: Schema.String });
export type KeyPair = typeof KeyPair.Type;

/** A fresh Ed25519 pair as PEM: PKCS#8 private, SPKI public (the form the relay expects). */
export const generateKeyPair = Jwk.generateKeyPair({ algorithm: "EdDSA" }).pipe(
  Effect.flatMap((pair) =>
    Effect.all({
      privateKey: Jwk.importPrivate(pair.privateKey, "EdDSA").pipe(
        Effect.flatMap((key) => Jwk.exportPkcs8(key, { format: "pem" })),
        Effect.map(Redacted.value),
      ),
      publicKey: Jwk.importPublic(pair.publicKey, "EdDSA").pipe(
        Effect.flatMap((key) => Jwk.exportSpki(key, { format: "pem" })),
      ),
    }),
  ),
  Effect.mapError(
    (cause) => new PluginError({ message: "Could not create a signing key.", cause }),
  ),
);

export const signJwt = (input: {
  readonly privateKeyPem: string;
  readonly typ: string;
  readonly payload: Readonly<Record<string, unknown>>;
}) =>
  Jwk.importPkcs8(Redacted.make(normalizePem(input.privateKeyPem)), "EdDSA").pipe(
    Effect.flatMap((key) =>
      Jws.sign(new TextEncoder().encode(JSON.stringify(input.payload)), key, { typ: input.typ }),
    ),
    Effect.map(Redacted.value),
    Effect.mapError(
      (cause) => new PluginError({ message: "Could not sign a T3 Connect proof.", cause }),
    ),
  );

export const verifyJwt = <A>(
  schema: Schema.ConstraintDecoder<A>,
  input: {
    readonly publicKeyPem: string;
    readonly token: string;
    readonly typ: string;
    readonly issuer: string;
    readonly audience: string;
  },
) =>
  Jwk.importSpki(normalizePem(input.publicKeyPem), "EdDSA").pipe(
    Effect.flatMap((key) =>
      Jwt.verify(schema, input.token, key, {
        typ: input.typ,
        issuer: input.issuer,
        audience: input.audience,
        maxTokenAge: "5 minutes",
        clockTolerance: "60 seconds",
      }),
    ),
    Effect.map((verified) => verified.claims),
  );

/** Unverified `iat`, so a proof can borrow the relay's clock. Never authorize on it. */
export const unverifiedIssuedAt = (token: string) =>
  Jwt.decodeUnverified(token).pipe(
    Effect.map(({ claims }) =>
      typeof claims.iat === "number" && Number.isSafeInteger(claims.iat) && claims.iat > 0
        ? claims.iat
        : null,
    ),
    Effect.orElseSucceed(() => null),
  );

export const isValidPublicKey = (pem: string) =>
  Jwk.importSpki(normalizePem(pem), "EdDSA").pipe(
    Effect.as(true),
    Effect.orElseSucceed(() => false),
  );

const MAX_PROOF_LIFETIME_SECONDS = 5 * 60;
const CLOCK_SKEW_SECONDS = 60;

/** The relay signs short proofs; reject one that claims a long life or a future issue time. */
export function hasBoundedLifetime(input: {
  readonly iat: number;
  readonly exp: number;
  readonly nowSeconds: number;
}): boolean {
  return (
    input.exp > input.iat &&
    input.exp - input.iat <= MAX_PROOF_LIFETIME_SECONDS &&
    input.iat <= input.nowSeconds + CLOCK_SKEW_SECONDS
  );
}

export function hasExactScope(scopes: ReadonlyArray<string>, expected: string): boolean {
  return scopes.length === 1 && scopes[0] === expected;
}
