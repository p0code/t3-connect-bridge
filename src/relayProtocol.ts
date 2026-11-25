/**
 * The slice of upstream T3 Connect's relay protocol this bridge speaks (pingdotgg/t3code
 * `packages/contracts/src/relay.ts` at ddaba134). Field names are the relay's wire format.
 */
import { EnvironmentId, ThreadId, TrimmedNonEmptyString } from "@t3tools/contracts";
import * as Schema from "effect/Schema";

export const RELAY_LINK_PROOF_TYP = "t3-env-link+jwt";
export const RELAY_MINT_REQUEST_TYP = "t3-cloud-mint+jwt";
export const RELAY_HEALTH_REQUEST_TYP = "t3-cloud-health+jwt";
export const RELAY_MINT_RESPONSE_TYP = "t3-env-mint+jwt";
export const RELAY_HEALTH_RESPONSE_TYP = "t3-env-health+jwt";
export const RELAY_ACTIVITY_PUBLISH_TYP = "t3-env-activity+jwt";

/** Paths the relay calls on the environment through the managed tunnel. */
export const HEALTH_ROUTE = "/api/t3-connect/health";
export const MINT_ROUTE = "/api/t3-connect/mint-credential";

export const ManagedEndpoint = Schema.Struct({
  httpBaseUrl: TrimmedNonEmptyString,
  wsBaseUrl: TrimmedNonEmptyString,
  providerKind: Schema.Literals(["manual", "cloudflare_tunnel", "t3_relay"]),
});

export const ManagedEndpointOrigin = Schema.Struct({
  localHttpHost: TrimmedNonEmptyString,
  localHttpPort: Schema.Int.check(
    Schema.isGreaterThanOrEqualTo(1),
    Schema.isLessThanOrEqualTo(65_535),
  ),
});
export type ManagedEndpointOrigin = typeof ManagedEndpointOrigin.Type;

export const ManagedEndpointRuntimeConfig = Schema.Struct({
  providerKind: Schema.Literals(["manual", "cloudflare_tunnel", "t3_relay"]),
  connectorToken: TrimmedNonEmptyString,
  tunnelId: Schema.optional(TrimmedNonEmptyString),
  tunnelName: Schema.optional(TrimmedNonEmptyString),
});
export type ManagedEndpointRuntimeConfig = typeof ManagedEndpointRuntimeConfig.Type;

export const LinkChallengeResponse = Schema.Struct({
  challenge: TrimmedNonEmptyString,
  expiresAt: TrimmedNonEmptyString,
});

export const LinkResponse = Schema.Struct({
  ok: Schema.Boolean,
  cloudUserId: TrimmedNonEmptyString,
  environmentId: EnvironmentId,
  endpoint: ManagedEndpoint,
  endpointRuntime: Schema.NullOr(ManagedEndpointRuntimeConfig),
  relayIssuer: TrimmedNonEmptyString,
  environmentCredential: TrimmedNonEmptyString,
  cloudMintPublicKey: TrimmedNonEmptyString,
});
export type LinkResponse = typeof LinkResponse.Type;

export const OkResponse = Schema.Struct({ ok: Schema.Boolean });

const RegisteredClaims = {
  iss: TrimmedNonEmptyString,
  aud: TrimmedNonEmptyString,
  sub: TrimmedNonEmptyString,
  jti: TrimmedNonEmptyString,
  iat: Schema.Int,
  exp: Schema.Int,
} as const;

export const MintCredentialProofPayload = Schema.Struct({
  ...RegisteredClaims,
  environmentId: EnvironmentId,
  clientProofKeyThumbprint: TrimmedNonEmptyString,
  cnf: Schema.Struct({ jkt: TrimmedNonEmptyString }),
  deviceId: Schema.optional(TrimmedNonEmptyString),
  nonce: TrimmedNonEmptyString,
  scope: Schema.Array(Schema.Literal("environment:connect")),
});

export const HealthProofPayload = Schema.Struct({
  ...RegisteredClaims,
  environmentId: EnvironmentId,
  nonce: TrimmedNonEmptyString,
  scope: Schema.Array(Schema.Literal("environment:status")),
});

export const ProofRequest = Schema.Struct({ proof: TrimmedNonEmptyString });

export const AgentActivityState = Schema.Struct({
  environmentId: EnvironmentId,
  threadId: ThreadId,
  projectTitle: TrimmedNonEmptyString,
  threadTitle: TrimmedNonEmptyString,
  phase: Schema.Literals([
    "starting",
    "running",
    "waiting_for_approval",
    "waiting_for_input",
    "completed",
    "failed",
    "stale",
  ]),
  headline: TrimmedNonEmptyString,
  detail: Schema.optional(TrimmedNonEmptyString),
  modelTitle: TrimmedNonEmptyString,
  updatedAt: TrimmedNonEmptyString,
  deepLink: TrimmedNonEmptyString,
});
export type AgentActivityState = typeof AgentActivityState.Type;

export const PublishResponse = Schema.Struct({ ok: Schema.Boolean });

/** The relay's error body; only the parts worth showing. */
export const RelayErrorBody = Schema.Struct({
  _tag: Schema.String,
  traceId: Schema.optional(Schema.String),
});
