import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

export const T3_CONNECT_BRIDGE_ID = "t3-connect-bridge";

/** Public values from upstream T3 Code's `.env.example`; overridable for a compatible service. */
export const BridgeConfig = Schema.Struct({
  relayUrl: Schema.String.pipe(
    Schema.withDecodingDefault(Effect.succeed("https://relay.t3.codes")),
  ),
  clerkPublishableKey: Schema.String.pipe(
    Schema.withDecodingDefault(Effect.succeed("pk_live_Y2xlcmsudDMuY29kZXMk")),
  ),
  cliOAuthClientId: Schema.String.pipe(
    Schema.withDecodingDefault(Effect.succeed("hzxSgY2cH10sDU2r")),
  ),
  hostedAppUrl: Schema.String.pipe(
    Schema.withDecodingDefault(Effect.succeed("https://app.t3.codes")),
  ),
  pushNotifications: Schema.Boolean.pipe(Schema.withDecodingDefault(Effect.succeed(true))),
});
export type BridgeConfig = typeof BridgeConfig.Type;

export const BridgeTunnelState = Schema.Literals(["off", "starting", "connected", "failed"]);
export type BridgeTunnelState = typeof BridgeTunnelState.Type;

export const BridgeStatus = Schema.Struct({
  account: Schema.NullOr(Schema.String),
  signedIn: Schema.Boolean,
  /** A device code waiting to be approved in the browser. */
  pendingSignIn: Schema.NullOr(
    Schema.Struct({
      verificationUrl: Schema.String,
      userCode: Schema.String,
    }),
  ),
  linked: Schema.Boolean,
  tunnel: BridgeTunnelState,
  hostname: Schema.NullOr(Schema.String),
  error: Schema.NullOr(Schema.String),
  config: BridgeConfig,
});
export type BridgeStatus = typeof BridgeStatus.Type;

const NoInput = Schema.Struct({});

export const BridgeConfigPatch = Schema.Struct({
  relayUrl: Schema.optionalKey(Schema.String),
  clerkPublishableKey: Schema.optionalKey(Schema.String),
  cliOAuthClientId: Schema.optionalKey(Schema.String),
  hostedAppUrl: Schema.optionalKey(Schema.String),
  pushNotifications: Schema.optionalKey(Schema.Boolean),
});
export type BridgeConfigPatch = typeof BridgeConfigPatch.Type;

/** The actions the settings panel calls through `plugins.invoke`. */
export const bridgeActions = {
  status: { input: NoInput, output: BridgeStatus },
  signIn: { input: NoInput, output: BridgeStatus },
  signOut: { input: NoInput, output: BridgeStatus },
  link: { input: NoInput, output: BridgeStatus },
  unlink: { input: NoInput, output: BridgeStatus },
  setConfig: { input: BridgeConfigPatch, output: BridgeStatus },
} as const;
export type BridgeAction = keyof typeof bridgeActions;
