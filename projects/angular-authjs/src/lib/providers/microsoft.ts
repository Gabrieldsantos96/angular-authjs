import { ProviderBaseEnvironment } from '../interfaces';
import { OAuthProviderClass } from "./abstract-class";

type OutlookProviderConfig = {
    tenant: string;
} & ProviderBaseEnvironment

export class OutlookOAuthProvider extends OAuthProviderClass<OutlookProviderConfig> {
    getEndpoints() {
        const tenant = (this.config as OutlookProviderConfig).tenant || 'common';
        return {
            authorizeUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
            tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
            userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
        };
    }

    authorize(callbackUrl: string = '/'): string {
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: 'openid profile email offline_access User.Read',
        } as unknown as Record<string, string>);

        const state = Buffer.from(JSON.stringify({ callbackUrl, timestamp: Date.now() })).toString('base64');
        params.append('state', state);

        return `${this.endpoints.authorizeUrl}?${params.toString()}`;
    }

    async callback<T>(code: string): Promise<T | null> {
        try {
            const result = await fetch(this.endpoints.tokenUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    code,
                    client_id: this.config.clientId,
                    client_secret: this.config.clientSecret,
                    redirect_uri: this.config.redirectUri,
                    grant_type: 'authorization_code',
                } as unknown as Record<string, string>).toString(),
            }).then((res) => res.json());


            if (!result.access_token) {
                console.error('Outlook OAuth: No access token received.');
                return null;
            }

            const userInfo = await fetch(this.endpoints.userInfoUrl, {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${result.access_token}`,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Express-App',
                },
            }).then((res) => res.json());

            if (!userInfo.id) {
                console.error('Outlook OAuth: Failed to fetch user info.');
                return null;
            }

            return {
                user: {
                    email: userInfo.mail,
                    name: userInfo.displayName,
                },
                expires: result.expires_in,
                access_token: result.access_token,
                id_token: result.id_token,
            } as T;
        } catch (err) {
            console.error('Outlook OAuth error:', err);
            return null;
        }
    }
}