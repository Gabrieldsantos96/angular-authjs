import { inject, Injectable, makeStateKey, PLATFORM_ID, Provider, REQUEST_CONTEXT, TransferState } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, BehaviorSubject, map, tap, catchError, of, take } from 'rxjs';
import { ProviderId, Session, SignInCommand } from './interfaces';
import { isPlatformServer } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';

const SESSION_KEY = makeStateKey<Session>('session');

type IRequestContext = {
  context: {
    session: Session;
  };
};

@Injectable({ providedIn: 'root' })

export class SessionProvider {
  private readonly platformId = inject(PLATFORM_ID);
  private readonly transferState = inject(TransferState);
  private readonly activatedRoute = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly http = inject(HttpClient)
  private readonly context = inject(REQUEST_CONTEXT, { optional: true }) as unknown as IRequestContext;
  private sessionSubject = new BehaviorSubject<Session | null>(null);
  readonly session$ = this.sessionSubject.asObservable();
  readonly sessionValue = this.sessionSubject.value;
  readonly isAuthenticated = !!this.sessionValue?.user
  readonly isAuthenticated$ = this.session$.pipe(map(session => !!session?.user));

  constructor() {

    this.activatedRoute.queryParams.pipe(take(1)).subscribe(params => {
      const redirectTo = params['redirectTo'];

      if (!!redirectTo) {
        let callbackUrl = redirectTo;

        this.getSession().pipe(take(1)).subscribe(session => {
          if (!!session && session.user) {
            this.router.navigateByUrl(callbackUrl);
          }
        });
      }
    });

  }

  getSession(): Observable<Session | null> {
    if (isPlatformServer(this.platformId)) {
      const session = this.context?.context?.session as Session | null;
      if (session) {
        this.transferState.set(SESSION_KEY, session);
        this.sessionSubject.next(session);
        return of(session);
      }
      return of(null);
    } else {
      if (this.transferState.hasKey(SESSION_KEY)) {
        const session = this.transferState.get(SESSION_KEY, null);
        this.sessionSubject.next(session);
        return of(session);
      } else {
        return this.http.get<Session | null>('/api/auth/session', { withCredentials: true }).pipe(
          tap(session => {
            this.sessionSubject.next(session);
            this.transferState.set(SESSION_KEY, session);
          }),
          catchError(() => {
            this.sessionSubject.next(null);
            return of(null);
          })
        );
      }
    }
  }

  _signIn(
    providerId: ProviderId,
    params: {
      username?: string;
      password?: string;
      code?: string;
      callbackUrl?: string;
    }
  ): Observable<{ success: boolean; error: Error | null }> {
    return this.http.post<{ redirectUri: string }>(
      `/api/auth/sign-in/${providerId}`,
      params,
      { withCredentials: true }
    ).pipe(
      map(result => {
        return { success: true, error: null, redirectUrl: result.redirectUri, callbackUrl: params.callbackUrl };
      }),
      catchError((error: unknown) => {
        const err = error as Error;
        this.sessionSubject.next(null);
        return of({ success: false, error: err });
      })
    );
  }

  signIn(formData: SignInCommand) {
    const signInData: Record<string, string> = {};

    if (formData.provider === ProviderId.credentials) {
      if (!formData.username || !formData.password) {
        console.error('Username and password are required for credentials provider');
        return;
      }
      signInData['username'] = formData.username;
      signInData['password'] = formData.password;
    }

    if (formData.callbackUrl) {
      signInData['callbackUrl'] = formData.callbackUrl;
    }

    signInData['provider'] = formData.provider;

    this._signIn(formData.provider, signInData).subscribe({
      next: (res: unknown) => {
        const result = res as Record<string, string>;
        window.location.href = result['redirectUrl'];
      },
      error: (err) => {
        console.error(`Login error for ${formData.provider}:`, err);
      },
    });
  }

  signOut(callbackUrl: string = '/'): Observable<string> {
    return this.http.post<string>('/api/auth/sign-out', { callbackUrl });
  }

}
