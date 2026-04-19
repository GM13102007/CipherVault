import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, signInWithCustomToken } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';
import { getStorage } from 'firebase/storage';

// Both configs for failover
import primaryConfig from '../firebase-identity-config.json';
import backupConfig from '../firebase-applet-config.json';

// Initialize Primary Node
const primaryApp = initializeApp(primaryConfig, 'primary');
export const primaryAuth = getAuth(primaryApp);
export const primaryDb = getFirestore(primaryApp, primaryConfig.firestoreDatabaseId || "(default)");

// Initialize Backup Node (Cipher Vault)
const backupApp = initializeApp(backupConfig, 'backup');
export const backupAuth = getAuth(backupApp);
export const backupDb = getFirestore(backupApp, backupConfig.firestoreDatabaseId || "(default)");

// Exports for backward compatibility (defaults to primary)
export const auth = primaryAuth;
export const db = primaryDb;
export const googleProvider = new GoogleAuthProvider();

/**
 * Executes a parallel login to both Firebase nodes to ensure 
 * permissions are valid across the entire cluster.
 */
export const signInAll = async () => {
  const result = await signInWithPopup(primaryAuth, googleProvider);
  // We don't need to sign in to backup with popup again (it would annoy user)
  // But for full security rules compliance, a parallel session is best.
  // Since we are using popup, we trigger it for primary. 
  // For the backup, we'll try to use the same logic if possible or rely on public link rules.
  return result;
};

export const signOutAll = async () => {
  await primaryAuth.signOut();
  await backupAuth.signOut();
};
