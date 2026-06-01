import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, signInAnonymously, signInWithRedirect } from 'firebase/auth';
import { initializeFirestore } from 'firebase/firestore';

// Main applet config
import config from '../firebase-applet-config.json';

// Initialize single Firebase instance
const app = getApps().length === 0 ? initializeApp(config) : getApp();
export const auth = getAuth(app);
export const db = initializeFirestore(app, {
  experimentalForceLongPolling: true,
  useFetchStreams: false,
} as any, config.firestoreDatabaseId || "(default)");

export const googleProvider = new GoogleAuthProvider();

export const signInAll = async () => {
  const isIframe = window.self !== window.top;

  // Inside iframe, standard popups can't communicate with parents, so force redirect
  if (isIframe) {
    try {
      return await signInWithRedirect(auth, googleProvider);
    } catch (redirectErr) {
      console.warn("Iframe redirect sign in failed", redirectErr);
    }
  }

  try {
    // 1. Try popup first (works perfectly on mobile Chrome/Safari when clicked by user, and preserves session context)
    return await signInWithPopup(auth, googleProvider);
  } catch (err: any) {
    console.warn("Popup authentication failed, attempting fallback...", err.code || err.message);
    
    // 2. Fall back to redirect only if popup is blocked or explicitly disallowed
    if (
      err.code === 'auth/popup-blocked' || 
      err.code === 'auth/cancelled-popup-request' || 
      err.code === 'auth/popup-closed-by-user' ||
      err.message?.includes('popup')
    ) {
      console.log("Popup blocked or closed, invoking redirect fallback...");
      return await signInWithRedirect(auth, googleProvider);
    }
    throw err;
  }
};

export const signInAnonymous = async () => {
  return await signInAnonymously(auth);
};

export const signOutAll = async () => {
  await auth.signOut();
};
