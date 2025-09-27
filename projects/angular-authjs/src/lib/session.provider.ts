import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject, map } from 'rxjs';
import { ProviderId, Session } from './interfaces';

@Injectable({ providedIn: 'root' })

export class SessionProvider {
  private sessionSubject = new BehaviorSubject<Session | null>(null);
  readonly session$ = this.sessionSubject.asObservable();
  readonly sessionValue = this.sessionSubject.value;
  readonly isAuthenticated = !!this.sessionValue?.user
  readonly isAuthenticated$ = this.session$.pipe(map(session => !!session?.user));

  constructor(private http: HttpClient) { }

  getSession(): Observable<Session> {
    return this.http.get<Session>('/api/auth/session');
  }

  signIn(
    providerId: ProviderId,
    params: {
      username?: string;
      password?: string;
      code?: string;
      callbackUrl?: string;
    }
  ): Observable<{ redirectTo: string }> {
    return this.http.post<{ redirectTo: string }>(
      `/api/auth/sign-in/${providerId}`,
      params
    );
  }

  signOut(callbackUrl: string = '/'): Observable<string> {
    return this.http.post<string>('/api/auth/sign-out', { callbackUrl });
  }

}
