import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { ProviderId, Session } from './interfaces';

@Injectable({ providedIn: 'root' })
export class SessionProvider {
  private session = signal<Session | null>(null);

  constructor(private http: HttpClient) {}

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
    return this.http.post<string>('/api/auth/sign-out', { callbackUrl }).pipe(
      tap(() => this.session.set(null)),
      catchError((error) => throwError(() => error))
    );
  }

  isAuthenticated(): boolean {
    return !!this.session();
  }
}
