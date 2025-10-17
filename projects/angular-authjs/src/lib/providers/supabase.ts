import { ProviderBaseEnvironment, SupabaseProviderConfig } from "../interfaces";
import { OAuthProviderClass } from "./abstract-class"

type SupbaseProviderConfig = {
    supabaseUrl: string;
} & ProviderBaseEnvironment

export class SupabaseOAuthProvider extends OAuthProviderClass<SupabaseProviderConfig> {
    getEndpoints() {
        const baseUrl = (this.config as SupbaseProviderConfig).supabaseUrl;
        return {
            authorizeUrl: `${baseUrl}/auth/v1/authorize`,
            tokenUrl: `${baseUrl}/auth/v1/token`,
            userInfoUrl: `${baseUrl}/auth/v1/user`,
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
            const resp = await fetch(this.endpoints.tokenUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    code,
                    client_id: this.config.clientId,
                    client_secret: this.config.clientSecret,
                    redirect_uri: this.config.redirectUri,
                    grant_type: 'authorization_code',
                }),
            }).then((res) => res.json());

            const accessToken = resp.access_token;

            if (!accessToken) {
                console.error('Supabase OAuth: No access token received.');
                return null;
            }

            const userInfo = await fetch(this.endpoints.userInfoUrl, {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    'Content-Type': 'application/json',
                },
            }).then((res) => res.json());

            if (!userInfo.id) {
                console.error('Supabase OAuth: Failed to fetch user info.');
                return null;
            }

            const email = userInfo.email;
            const name = userInfo.user_metadata?.name || userInfo.raw_user_metadata?.name;

            return {
                ...userInfo,
                email,
                name,
                access_token: accessToken,
                refresh_token: resp.refresh_token,
            } as T;
        } catch (err) {
            console.error('Supabase OAuth error:', err);
            return null;
        }
    }
}