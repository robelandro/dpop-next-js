import { NextResponse } from 'next/server';
import { COOKIE_NAME } from '@/lib/server/jwt';

export async function POST() {
  const response = NextResponse.json({
    success: true,
    message: 'Logged out successfully. DPoP session cookie removed.',
  });

  response.cookies.set({
    name: COOKIE_NAME,
    value: '',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });

  return response;
}
