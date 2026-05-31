import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, signInAnonymously } from 'firebase/auth';
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
  return await signInWithPopup(auth, googleProvider);
};

export const signInAnonymous = async () => {
  return await signInAnonymously(auth);
};

export const signOutAll = async () => {
  await auth.signOut();
};
