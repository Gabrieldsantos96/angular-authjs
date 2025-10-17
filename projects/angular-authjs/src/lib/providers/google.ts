// google-provider.ts
import { OAuthProviderConfig } from "../interfaces";
import { OAuthProviderClass } from "./abstract-class"

export class GoogleOAuthProvider extends OAuthProviderClass<OAuthProviderConfig> {
    getEndpoints() {
        return {
            authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenUrl: 'https://oauth2.googleapis.com/token',
            userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
        };
    }

    authorize(callbackUrl: string = '/'): string {
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: 'openid email profile',

        } as unknown as Record<string, string>);
        const state = Buffer.from(JSON.stringify({ callbackUrl, timestamp: Date.now() })).toString('base64');
        params.append('state', state);
        return `${this.endpoints.authorizeUrl}?${params.toString()}`;
    }

    async callback<T>(code: string): Promise<T | null> {
        try {
            const result = await fetch(this.endpoints.tokenUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code,
                    client_id: this.config.clientId,
                    client_secret: this.config.clientSecret,
                    redirect_uri: this.config.redirectUri,
                    grant_type: 'authorization_code',
                }),
            }).then((res) => res.json());

            if (!result.access_token) {
                console.error('Google OAuth: No access token received');
                return null;
            }

            const user = await fetch(this.endpoints.userInfoUrl, {
                method: 'GET',
                headers: { Authorization: `Bearer ${result.access_token}` },
            }).then((res) => res.json());

            if (!user.email_verified) {
                console.error('Google OAuth: Email not verified');
                return null;
            }

            const { name, picture: image, email } = user
            const { access_token, id_token, expires_in } = result;

            return {
                user: {
                    name,
                    email,
                    image,
                }, access_token, id_token, expires: expires_in
            } as T;

        } catch (err) {
            console.error('Google OAuth error:', err);
            return null;
        }
    }
}

