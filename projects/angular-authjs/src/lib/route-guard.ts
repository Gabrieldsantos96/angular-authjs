// src/lib/route.guard.ts
import {
  PLATFORM_ID,
  makeStateKey,
  TransferState,
  inject,
  REQUEST_CONTEXT,
} from '@angular/core';
import { CanActivateFn } from '@angular/router';
import { isPlatformServer } from '@angular/common';

type IRequestContext = {
  context: {
    session: any;
  };
};

const SESSION_KEY = makeStateKey<any>('session');

export const RouteGuard: CanActivateFn = () => {
  const platformId = inject(PLATFORM_ID);
  const transferState = inject(TransferState);
  const ctx = inject(REQUEST_CONTEXT, { optional: true }) as unknown as IRequestContext;

  if (isPlatformServer(platformId)) {
    const session = ctx?.context?.session as any | null;

    if (!session) return false;

    transferState.set(SESSION_KEY, session);
    
    return true;

  } else {
    return transferState.hasKey(SESSION_KEY);
  }
};