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
  // Check if we are on a mobile device or if popup blocker might trigger
  const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
  const isIframe = window.self !== window.top;

  if (isMobile || isIframe) {
    try {
      return await signInWithRedirect(auth, googleProvider);
    } catch (redirectErr) {
      console.warn("Redirect sign in failed, trying popup", redirectErr);
    }
  }

  try {
    return await signInWithPopup(auth, googleProvider);
  } catch (err: any) {
    // Fallback to Redirect if popup is blocked
    if (err.code === 'auth/popup-blocked' || err.code === 'auth/cancelled-popup-request') {
      console.log("Popup blocked or cancelled, falling back to redirect login...");
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
