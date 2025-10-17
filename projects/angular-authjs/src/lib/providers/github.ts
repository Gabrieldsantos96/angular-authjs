// github-provider.ts
import { OAuthProviderConfig } from "../interfaces";
import { OAuthProviderClass } from "./abstract-class"

export class GitHubOAuthProvider extends OAuthProviderClass<OAuthProviderConfig> {
    getEndpoints() {
        return {
            authorizeUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
            userInfoUrl: 'https://api.github.com/user',
        };
    }

    authorize(callbackUrl: string = '/'): string {
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.redirectUri,
            response_type: 'code',
            scope: 'user:email',
            callbackUrl

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
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body: JSON.stringify({
                    code,
                    client_id: this.config.clientId,
                    client_secret: this.config.clientSecret,
                    redirect_uri: this.config.redirectUri,
                    grant_type: 'authorization_code',
                }),
            }).then((res) => res.json());

            if (!result.access_token) {
                console.error('GitHub OAuth: No access token received.');
                return null;
            }

            const userInfo = await fetch(this.endpoints.userInfoUrl, {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${result.access_token}`,
                    'User-Agent': 'Express-App',
                },
            }).then((res) => res.json());



            if (!userInfo.id) {
                console.error('GitHub OAuth: Failed to fetch user info.');
                return null;
            }

            let _email = userInfo?.email;

            if (!_email) {
                const emails = await fetch('https://api.github.com/user/emails', {
                    headers: {
                        Authorization: `Bearer ${result.access_token}`,
                        'User-Agent': 'Express-App',
                    },
                }).then((res) => res.json());

                _email = emails.find((e: {
                    email: string,
                    primary: boolean,
                    verified: boolean,
                    visibility: 'private' | null
                }) => e.primary);
            }

            if (!_email.verified) {
                console.error('GitHub OAuth: Email not verified.');
                return null;
            }
            const { access_token } = result;
            const { email } = _email
            const { name, avatar_url: image } = userInfo;

            return {
                user: {
                    name,
                    email,
                    image,
                }, access_token,
                expires: 3599
            } as T;
        } catch (err) {
            console.error('GitHub OAuth error:', err);
            return null;
        }
    }
}