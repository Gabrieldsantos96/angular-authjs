// credentials-provider.ts
import { CredentialsProviderConfig, Session } from '../interfaces';
import { OAuthProviderClass } from './abstract-class';



export class CredentialsAuthProvider extends OAuthProviderClass<CredentialsProviderConfig> {
    getEndpoints() {
        return {
            authorizeUrl: '',
            tokenUrl: '',
            userInfoUrl: '',
        };
    }

    async authorize(data: any): Promise<Session | null> {
        try {
            if (!data.username || !data.password) {
                console.error('Credentials provider: Missing username or password.');
                return null;
            }

            const { backendUrl } = this.config as CredentialsProviderConfig;
            const response = await fetch(`${backendUrl}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: data.username,
                    password: data.password,
                }),
            });

            if (!response.ok) {
                console.error('Credentials provider: Authentication failed.', response.statusText);
                return null;
            }

            const session: Session = await response.json();
            if (!session || !session.user) {
                console.error('Credentials provider: Invalid response.');
                return null;
            }

            return {
                user: {
                    name: session.user.name,
                    email: session.user.email,
                    image: session.user.image,
                },
                expires: session.expires,
            };
        } catch (err) {
            console.error('Credentials auth error:', err);
            return null;
        }
    }

    callback<T>(code: string): Promise<T | null> {
        throw new Error('Credentials provider does not support OAuth callback.');
    }
}