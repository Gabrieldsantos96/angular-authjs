import { ProviderBaseEnvironment, Session, SignInCommand } from "../interfaces";

export abstract class OAuthProviderClass<T extends ProviderBaseEnvironment = ProviderBaseEnvironment> {
  public config: T;
  public endpoints: {
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
  };

  constructor(config: T) {
    this.config = config;
    this.endpoints = this.getEndpoints();
  }

  public abstract getEndpoints(): {
    authorizeUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
  };

  abstract authorize(data?: SignInCommand | string): Promise<Session | null> | string;

  abstract callback<T>(code: string): Promise<T | null>;
}

