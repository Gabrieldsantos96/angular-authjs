/*
 * Public API Surface of angular-authjs
 */
export { createAuthenticationRouter } from "./lib/[...auth]"
export * from "./lib/interfaces"
export { createJwt, verifyJwt } from "./lib/jwt-helper"
export { session } from "./lib/middlewares"
export { CredentialsAuthProvider, GitHubOAuthProvider, GoogleOAuthProvider, OAuthProviderClass } from "./lib/providers"
export { RouteGuard } from "./lib/route-guard"
export { SessionProvider } from "./lib/session.provider"
