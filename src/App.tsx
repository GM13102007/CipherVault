/**
 * CipherVault: Zero-Knowledge Secure File Sharing
 * Client-side AES-256-GCM encryption
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Shield, 
  Lock, 
  Unlock, 
  Upload, 
  Download, 
  Copy, 
  Check, 
  Loader2, 
  AlertCircle,
  Clock,
  FileText,
  Image as ImageIcon,
  Film,
  Trash2,
  Share2,
  Info,
  ShieldAlert,
  Terminal
} from 'lucide-react';
import { 
  doc, 
  setDoc, 
  getDoc, 
  deleteDoc,
  collection,
  getDocs,
  writeBatch,
  query,
  where,
  serverTimestamp, 
  Timestamp
} from 'firebase/firestore';
import { auth, db, signIn, signOut } from './firebase';
import { onAuthStateChanged, User } from 'firebase/auth';
import { encryptData, decryptData, arrayBufferToBase64, base64ToArrayBuffer } from './lib/crypto';
import { handleFirestoreError, OperationType } from './lib/errorHandlers';

// --- Types ---

interface ShareData {
  id: string;
  iv: string;
  chunkCount: number;
  fileName: string;
  mimeType: string;
  size: number;
  createdAt: any;
  expiresAt: any;
  ownerId?: string;
}

interface ChunkData {
  data: string;
  index: number;
}

// --- Helper Components ---

function AdminDashboard({ onPrune }: { onPrune: () => Promise<void> }) {
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  const handlePrune = async () => {
    setLoading(true);
    await onPrune();
    setLoading(false);
    setDone(true);
    setTimeout(() => setDone(false), 3000);
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="mt-6 p-4 bg-red-500/5 border border-red-500/20 rounded-xl space-y-3"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-red-400 font-mono text-[10px] font-bold uppercase tracking-widest">
          <ShieldAlert className="w-3 h-3 glow-red animate-pulse" />
          Maintenance Terminal
        </div>
        <div className="text-[8px] px-1.5 py-0.5 bg-red-500/20 text-red-500 rounded font-bold uppercase tracking-tighter">Admin Locked</div>
      </div>
      <p className="text-[10px] text-slate-500 leading-tight">
        Scanner will identify and permanently eliminate all expired secure fragments and metadata from the core database.
      </p>
      <button 
        onClick={handlePrune}
        disabled={loading}
        className="w-full py-2 bg-red-600/20 hover:bg-red-600/30 text-red-500 border border-red-500/30 rounded font-mono text-[10px] uppercase font-bold tracking-widest transition-all flex items-center justify-center gap-2 disabled:opacity-50"
      >
        {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : done ? <Check className="w-3 h-3" /> : <Trash2 className="w-3 h-3" />}
        {loading ? 'Pruning Fragments...' : done ? 'Purge Complete' : 'Execute Global Prune'}
      </button>
    </motion.div>
  );
}

function Countdown({ expiresAt }: { expiresAt: any }) {
  const [timeLeft, setTimeLeft] = useState<string>('...');

  useEffect(() => {
    const target = expiresAt instanceof Timestamp ? expiresAt.toDate() : new Date(expiresAt);
    
    const updateTimer = () => {
      const now = new Date();
      const diff = target.getTime() - now.getTime();
      
      if (diff <= 0) {
        setTimeLeft('EXPIRED');
        return;
      }

      const h = Math.floor(diff / (1000 * 60 * 60));
      const m = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const s = Math.floor((diff % (1000 * 60)) / 1000);

      const parts = [];
      if (h > 0) parts.push(`${h}h`);
      if (m > 0 || h > 0) parts.push(`${m}m`);
      parts.push(`${s}s`);

      setTimeLeft(parts.join(' '));
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [expiresAt]);

  return <span>{timeLeft}</span>;
}

// --- Components ---

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [shareId, setShareId] = useState<string | null>(null);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [view, setView] = useState<'home' | 'upload' | 'download' | 'success'>('home');
  const [error, setError] = useState<string | null>(null);
  
  // Home/Receive State
  const [manualLink, setManualLink] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState<string | null>(null);
  const [expiryMinutes, setExpiryMinutes] = useState(60);
  const [generatedLink, setGeneratedLink] = useState('');

  // Download State
  const [targetShare, setTargetShare] = useState<ShareData | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedFile, setDecryptedFile] = useState<{ url: string; name: string } | null>(null);
  const [showAdmin, setShowAdmin] = useState(false);

  // --- Maintenance Rules ---
  const isAdmin = user?.email === 'transferd001@gmail.com';

  const pruneExpired = async () => {
    try {
      const sharesRef = collection(db, 'shares');
      const q = query(sharesRef, where('expiresAt', '<', Timestamp.now()));
      const snapshot = await getDocs(q);
      
      let deletedCount = 0;
      for (const shareDoc of snapshot.docs) {
        const id = shareDoc.id;
        const chunksSnap = await getDocs(collection(db, 'shares', id, 'chunks'));
        const batch = writeBatch(db);
        chunksSnap.forEach(chk => batch.delete(chk.ref));
        batch.delete(shareDoc.ref);
        await batch.commit();
        deletedCount++;
      }
      if (deletedCount > 0) console.log(`[MAINTENANCE] Pruned ${deletedCount} fragments.`);
    } catch (err) {
      console.error("Maintenance failed:", err);
    }
  };

  // --- Effects ---

  useEffect(() => {
    // Proactive maintenance
    if (isAdmin && view === 'home') {
      pruneExpired();
    }
  }, [isAdmin, view]);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (u) => {
      setUser(u);
      setLoading(false);
    });

    // Handle incoming share links
    // Format: /#share={id}&key={key}
    const handleHash = () => {
      const hash = window.location.hash.substring(1);
      if (!hash) {
        if (view !== 'home') setView('home');
        return;
      }

      console.log("CipherVault: Detecting secure handshake...");
      const params = new URLSearchParams(hash);
      const id = params.get('share');
      const key = params.get('key');

      if (id && key) {
        // Fix for Base64: URLSearchParams converts '+' to ' ' (space)
        const sanitizedKey = key.replace(/ /g, '+');
        
        console.log("CipherVault: Valid ID and Key found. Fetching metadata...");
        setShareId(id);
        setSecretKey(sanitizedKey);
        setView('download');
        loadShareMetadata(id);
      } else if (id || key) {
        console.warn("CipherVault: Incomplete link detected. Missing ID or Key.");
        setError("Invalid or incomplete secure link. Please check the URL.");
        setView('home');
      }
    };

    handleHash();
    window.addEventListener('hashchange', handleHash);
    return () => {
      unsubscribe();
      window.removeEventListener('hashchange', handleHash);
    };
  }, []);

  // --- Actions ---

  const loadShareMetadata = async (id: string) => {
    const path = `shares/${id}`;
    try {
      const docRef = doc(db, 'shares', id);
      const docSnap = await getDoc(docRef);

      if (docSnap.exists()) {
        const data = docSnap.data() as ShareData;
        
        // Check expiry
        const expiresAt = data.expiresAt instanceof Timestamp ? data.expiresAt.toDate() : new Date(data.expiresAt);
        if (expiresAt < new Date()) {
          setError('This secure share has expired and self-destructed.');
          
          // Lazy Deletion: Clean up chunks and metadata
          try {
            const chunksSnap = await getDocs(collection(db, 'shares', id, 'chunks'));
            const batch = writeBatch(db);
            chunksSnap.forEach(chk => batch.delete(chk.ref));
            batch.delete(docRef);
            await batch.commit();
          } catch (e) {
            console.warn("Cleanup failed, resource may already be gone.");
          }
          return;
        }

        setTargetShare(data);
      } else {
        setError('Share not found. It may have expired or been deleted.');
      }
    } catch (err) {
      console.error(err);
      if (err instanceof Error && err.message.includes('permissions')) {
        handleFirestoreError(err, OperationType.GET, path);
      }
      setError('Could not connect to the secure vault.');
    }
  };

  const handleFileUpload = async () => {
    if (!file) return;
    
    if (file.size > 10 * 1024 * 1024) {
      setError('File size exceeds safety limit (10MB).');
      return;
    }

    try {
      setIsEncrypting(true);
      setCurrentPhase("Encrypting data...");
      setError(null);

      const reader = new FileReader();
      const fileDataPromise = new Promise<ArrayBuffer>((resolve) => {
        reader.onload = () => resolve(reader.result as ArrayBuffer);
        reader.readAsArrayBuffer(file);
      });
      const arrayBuffer = await fileDataPromise;

      const { encryptedBuffer, iv, key } = await encryptData(arrayBuffer);
      
      setIsEncrypting(false);
      setIsUploading(true);
      setCurrentPhase("Preparing secure transmission...");
      setUploadProgress(0);

      const id = crypto.randomUUID();
      const createdAt = new Date();
      const expiresAt = new Date(createdAt.getTime() + expiryMinutes * 60 * 1000);

      // Split into 1MB Chunks (approx. base64 safe)
      const bufferView = new Uint8Array(encryptedBuffer!);
      const chunkSize = 700 * 1024; // Smaller for base64 head room in Firestore (1MB limit)
      const chunks: string[] = [];
      
      for (let i = 0; i < bufferView.length; i += chunkSize) {
        const chunk = bufferView.slice(i, i + chunkSize);
        chunks.push(arrayBufferToBase64(chunk.buffer));
      }

      const totalChunks = chunks.length;
      setCurrentPhase(`Transferring ${totalChunks} secure packets...`);

      // Upload Chunks
      for (let i = 0; i < chunks.length; i++) {
        setUploadProgress(((i + 1) / totalChunks) * 100);
        try {
          await setDoc(doc(db, 'shares', id, 'chunks', `c${i}`), {
            data: chunks[i],
            index: i
          });
        } catch (chkErr: any) {
          console.error("Chunk Upload Error:", chkErr);
          throw new Error(`Failed to upload packet ${i+1}/${totalChunks}: ${chkErr.message}`);
        }
      }

      setCurrentPhase("Finalizing secure terminal...");

      const shareObj: ShareData = {
        id,
        iv,
        chunkCount: totalChunks,
        fileName: file.name,
        mimeType: file.type,
        size: file.size,
        createdAt: serverTimestamp(),
        expiresAt: Timestamp.fromDate(expiresAt)
      };

      if (user?.uid) {
        shareObj.ownerId = user.uid;
      }

      try {
        await setDoc(doc(db, 'shares', id), shareObj);
      } catch (metaErr: any) {
        console.error("Metadata Upload Error:", metaErr);
        throw new Error(`Failed to finalize share: ${metaErr.message}`);
      }

      const link = `${window.location.origin}/#share=${id}&key=${encodeURIComponent(key)}`;
      setGeneratedLink(link);
      setView('success');
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Encryption or upload failed.');
    } finally {
      setIsEncrypting(false);
      setIsUploading(false);
      setCurrentPhase(null);
    }
  };

  const handleDownload = async () => {
    if (!targetShare || !secretKey) return;

    try {
      setIsDecrypting(true);
      setCurrentPhase("Downloading encrypted packets...");
      
      const chunksSnap = await getDocs(collection(db, 'shares', targetShare.id, 'chunks'));
      const chunksData = chunksSnap.docs
        .map(doc => doc.data() as ChunkData)
        .sort((a, b) => a.index - b.index);

      if (chunksData.length === 0) throw new Error("File parts missing or self-destructed.");

      setCurrentPhase("Reassembling file...");
      
      // Join chunks
      let totalLength = 0;
      const arrayBuffers = chunksData.map(c => {
        const buf = base64ToArrayBuffer(c.data);
        totalLength += buf.byteLength;
        return buf;
      });

      const combined = new Uint8Array(totalLength);
      let offset = 0;
      for (const buf of arrayBuffers) {
        combined.set(new Uint8Array(buf), offset);
        offset += buf.byteLength;
      }

      setCurrentPhase("Decrypting with secure key...");

      const decryptedBuffer = await decryptData(
        combined.buffer,
        targetShare.iv,
        secretKey
      );

      const blob = new Blob([decryptedBuffer], { type: targetShare.mimeType });
      const url = URL.createObjectURL(blob);
      
      setDecryptedFile({ url, name: targetShare.fileName });
      
      // Automatic download
      const a = document.createElement('a');
      a.href = url;
      a.download = targetShare.fileName;
      a.click();
    } catch (err) {
      console.error(err);
      setError('Decryption failed. The secret key might be invalid or storage is corrupt.');
    } finally {
      setIsDecrypting(false);
      setCurrentPhase(null);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // Simple toast could go here
  };

  const reset = () => {
    window.location.hash = '';
    setFile(null);
    setShareId(null);
    setSecretKey(null);
    setTargetShare(null);
    setGeneratedLink('');
    setDecryptedFile(null);
    setError(null);
    setManualLink('');
    setView('home');
  };

  const handleManualReceive = () => {
    try {
      if (!manualLink) return;
      
      const url = new URL(manualLink);
      const hash = url.hash.substring(1);
      const params = new URLSearchParams(hash);
      const id = params.get('share');
      const key = params.get('key');

      if (id && key) {
        // Fix for Base64: URLSearchParams/URL parsing converts '+' to ' ' (space)
        const sanitizedKey = key.replace(/ /g, '+');
        setShareId(id);
        setSecretKey(sanitizedKey);
        setView('download');
        loadShareMetadata(id);
      } else {
        setError("Could not parse link. Make sure it's a full CipherVault URL.");
      }
    } catch (err) {
      setError("Invalid URL format. Please paste the full link.");
    }
  };

  // --- Render Helpers ---

  const getFileIcon = (mime: string) => {
    if (mime.startsWith('image/')) return <ImageIcon className="w-8 h-8 text-blue-400" />;
    if (mime.startsWith('video/')) return <Film className="w-8 h-8 text-purple-400" />;
    return <FileText className="w-8 h-8 text-slate-400" />;
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  // --- Main Render ---

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#0d0e10]">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0d0e10] p-4 md:p-8 selection:bg-blue-500/30">
      {/* Header */}
      <nav className="max-w-4xl mx-auto flex justify-between items-center mb-12">
        <div className="flex items-center gap-2 cursor-pointer" onClick={reset}>
          <div className="p-2 bg-blue-500/10 rounded-lg technical-border">
            <Shield className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="font-mono font-bold tracking-tighter text-xl">CIPHERVAULT</h1>
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest leading-none">Zero-Knowledge Storage</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {user ? (
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono text-slate-400 hidden sm:inline truncate max-w-[100px]">{user.email}</span>
              <button 
                onClick={signOut}
                className="text-xs font-mono uppercase tracking-wider text-slate-500 hover:text-white transition-colors"
              >
                Disconnect
              </button>
              {isAdmin && (
                <button 
                  onClick={() => setShowAdmin(!showAdmin)}
                  className={`text-xs font-mono uppercase tracking-wider ${showAdmin ? 'text-red-400' : 'text-slate-500'} hover:text-white transition-colors flex items-center gap-1.5`}
                >
                  <Terminal className={`w-3 h-3 ${showAdmin ? 'glow-red' : ''}`} />
                  Terminal
                </button>
              )}
            </div>
          ) : (
            <button 
              onClick={signIn}
              className="text-xs font-mono uppercase tracking-wider bg-white/5 hover:bg-white/10 px-4 py-2 rounded-md border border-white/10 transition-all"
            >
              Sign In
            </button>
          )}
        </div>
      </nav>

      <main className="max-w-md mx-auto relative cursor-default">
        <AnimatePresence mode="wait">
          
          {/* Home View */}
          {view === 'home' && (
            <motion.div 
              key="home"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-6"
            >
              <div className="bg-[#151619] p-8 rounded-xl technical-border text-center">
                <div className="flex justify-center mb-6">
                  <div className="p-4 bg-blue-500/10 rounded-full border border-blue-500/20 shadow-[0_0_30px_rgba(59,130,246,0.1)]">
                    <Shield className="w-12 h-12 text-blue-500 animate-pulse-glow" />
                  </div>
                </div>
                <h2 className="text-2xl font-mono font-bold mb-2">ACCESS TERMINAL</h2>
                <p className="text-sm text-slate-400 mb-8 lowercase italic">Choose your operation mode</p>

                <div className="grid gap-4">
                    <button 
                      onClick={() => setView('upload')}
                      className="group bg-blue-600 hover:bg-blue-500 p-6 rounded-xl transition-all text-left flex items-center justify-between shadow-lg hover:shadow-blue-500/20"
                    >
                      <div>
                        <h3 className="font-mono font-bold text-lg leading-none mb-1">DEPOSIT DATA</h3>
                        <p className="text-[10px] uppercase font-mono tracking-widest text-blue-200 opacity-70">Encrypt & Store</p>
                      </div>
                      <Lock className="w-6 h-6 group-hover:scale-110 transition-transform glow-blue" />
                    </button>

                  <div className="relative">
                    <div className="absolute inset-0 flex items-center" aria-hidden="true">
                      <div className="w-full border-t border-white/10"></div>
                    </div>
                    <div className="relative flex justify-center">
                      <span className="bg-[#151619] px-4 text-[10px] font-mono text-slate-500 uppercase tracking-widest">or receive</span>
                    </div>
                  </div>

                  <div className="bg-white/5 p-6 rounded-xl border border-white/10 text-left">
                    <h3 className="font-mono font-bold text-lg leading-none mb-4 uppercase">Direct Extraction</h3>
                    <div className="flex gap-2">
                      <input 
                        type="text"
                        placeholder="Paste secure link here..."
                        value={manualLink}
                        onChange={(e) => setManualLink(e.target.value)}
                        className="flex-1 bg-black/40 border border-white/10 rounded-lg px-4 py-3 text-xs font-mono text-blue-400 placeholder:text-slate-600 focus:outline-none focus:border-blue-500/50"
                      />
                        <button 
                          onClick={handleManualReceive}
                          className="bg-white/10 hover:bg-white/20 p-3 rounded-lg transition-colors group-hover:bg-blue-500/10"
                        >
                          <Unlock className="w-5 h-5 group-hover:glow-blue transition-all" />
                        </button>
                    </div>
                    {error && view === 'home' && (
                      <p className="mt-3 text-[10px] text-red-400 font-mono uppercase tracking-wider">{error}</p>
                    )}
                  </div>
                </div>

                {isAdmin && showAdmin && (
                  <AdminDashboard onPrune={pruneExpired} />
                )}
              </div>

              <div className="grid grid-cols-3 gap-2">
                {[
                  { label: "AES-256", icon: Shield },
                  { label: "ZERO-K", icon: Lock },
                  { label: "SECURE", icon: Check }
                ].map((item, idx) => (
                  <div key={idx} className="bg-white/5 border border-white/5 p-3 rounded-lg flex flex-col items-center gap-1">
                    <item.icon className="w-4 h-4 text-slate-500" />
                    <span className="text-[8px] font-mono uppercase tracking-widest text-slate-400">{item.label}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}

          {/* Upload View */}
          {view === 'upload' && (
            <motion.div 
              key="upload"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="bg-[#151619] p-6 rounded-xl technical-border overflow-hidden"
            >
              <div className="scanning scanline" />
              <h2 className="text-lg font-mono font-bold flex items-center gap-2 mb-4">
                <Lock className="w-4 h-4 text-blue-500 glow-blue" />
                SECURE UPLOAD
              </h2>

              {error && (
                <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-md flex items-start gap-2 text-xs text-red-400">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <div 
                className={`group relative border-2 border-dashed transition-all duration-300 rounded-xl mb-6 flex flex-col items-center justify-center p-12 text-center
                  ${file ? 'border-blue-500/50 bg-blue-500/5' : 'border-white/10 hover:border-blue-500/30 hover:bg-white/5'}
                `}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  const f = e.dataTransfer.files[0];
                  if (f) setFile(f);
                }}
              >
                {!file ? (
                  <>
                    <div className="p-4 bg-white/5 rounded-full mb-4 group-hover:scale-110 transition-transform">
                      <Upload className="w-8 h-8 text-slate-500 group-hover:text-blue-500" />
                    </div>
                    <p className="text-sm text-slate-400 mb-1">Drag & drop your file here</p>
                    <p className="text-[10px] text-slate-600 uppercase font-mono">Max limit: 10MB</p>
                    <input 
                      type="file" 
                      className="absolute inset-0 opacity-0 cursor-pointer"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        if (f) setFile(f);
                      }}
                    />
                  </>
                ) : (
                  <div className="flex flex-col items-center">
                    {getFileIcon(file.type)}
                    <p className="mt-3 text-sm font-medium text-white max-w-[200px] truncate">{file.name}</p>
                    <p className="text-[10px] font-mono text-slate-500 mt-1">{formatSize(file.size)}</p>
                    <button 
                      onClick={() => setFile(null)}
                      className="mt-4 p-2 text-slate-500 hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                )}
              </div>

              {file && (
                <div className="space-y-6">
                  <div className="bg-black/40 p-4 rounded-xl border border-white/5 space-y-3">
                    <label className="text-[10px] font-mono text-slate-500 uppercase tracking-widest flex items-center justify-between">
                      <span>Self-Destruct Expiry</span>
                      <span className="text-blue-400 font-bold">{expiryMinutes} MIN</span>
                    </label>
                    <div className="flex gap-2">
                       <input 
                        type="number" 
                        min="1" 
                        max="1440" 
                        value={expiryMinutes}
                        onChange={(e) => setExpiryMinutes(Math.max(1, parseInt(e.target.value) || 1))}
                        className="flex-1 bg-white/5 technical-border rounded-lg px-4 py-2 text-xs font-mono text-white focus:outline-none focus:border-blue-500/50"
                      />
                      <div className="flex gap-1">
                        {[15, 60, 1440].map(m => (
                          <button 
                            key={m}
                            type="button"
                            onClick={() => setExpiryMinutes(m)}
                            className={`px-3 py-2 rounded-lg text-[9px] font-mono border transition-all ${expiryMinutes === m ? 'bg-blue-500/20 border-blue-500/50 text-blue-400' : 'bg-white/5 border-white/10 text-slate-500 hover:text-white'}`}
                          >
                            {m >= 60 ? (m/60) + 'H' : m + 'M'}
                          </button>
                        ))}
                      </div>
                    </div>
                    <p className="text-[9px] text-slate-600 italic">Enter minutes (e.g. 60 = 1 hour). Max 1440 (24H).</p>
                  </div>

                  <button
                    disabled={isEncrypting || isUploading}
                    onClick={handleFileUpload}
                    className={`w-full relative py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-mono font-bold uppercase tracking-wider text-xs transition-all disabled:opacity-50 disabled:cursor-not-allowed group overflow-hidden
                      ${isUploading || isEncrypting ? 'shadow-[0_0_20px_rgba(59,130,246,0.25)]' : 'shadow-lg'}
                    `}
                  >
                    <AnimatePresence mode="wait">
                      {isEncrypting ? (
                        <motion.div 
                          key="enc"
                          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                          className="flex flex-col items-center justify-center gap-2"
                        >
                          <div className="flex items-center gap-2">
                            <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                            <span>ENCRYPTING...</span>
                          </div>
                          <span className="text-[8px] opacity-50 tracking-widest text-white uppercase italic">Zero-Knowledge Ciphering</span>
                        </motion.div>
                      ) : isUploading ? (
                        <motion.div 
                          key="up"
                          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                          className="w-full space-y-2"
                        >
                          <div className="flex items-center justify-center gap-2">
                             <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                             <span className="uppercase">UPLOADING {Math.round(uploadProgress)}%</span>
                          </div>
                          <div className="w-full bg-black/40 h-1 rounded-full overflow-hidden border border-white/5">
                            <motion.div 
                              className="bg-blue-500 h-full"
                              initial={{ width: 0 }}
                              animate={{ width: `${uploadProgress}%` }}
                            />
                          </div>
                        </motion.div>
                      ) : (
                        <motion.div 
                          key="idle"
                          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                          className="flex items-center justify-center gap-2"
                        >
                          <Shield className="w-4 h-4" />
                          Secure & Share
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </button>
                </div>
              )}

              <div className="mt-8 pt-6 border-t border-white/5 flex items-start gap-3">
                <div className="p-2 bg-slate-500/10 rounded-md">
                  <Info className="w-3 h-3 text-slate-400" />
                </div>
                <p className="text-[10px] leading-relaxed text-slate-500">
                  Encryption is performed client-side using AES-GCM 256. The decryption key never leaves your browser and is only shared via the URL fragment (#).
                </p>
              </div>
            </motion.div>
          )}

          {/* Success View */}
          {view === 'success' && (
            <motion.div 
              key="success"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="bg-[#151619] p-6 rounded-xl technical-border"
            >
              <div className="flex flex-col items-center text-center mb-8">
                <div className="p-4 bg-green-500/10 rounded-full mb-4 shadow-[0_0_20px_rgba(34,197,94,0.1)]">
                  <Share2 className="w-10 h-10 text-green-500 filter drop-shadow-[0_0_8px_rgba(34,197,94,0.4)]" />
                </div>
                <h2 className="text-xl font-mono font-bold tracking-tight mb-2 uppercase text-white">Share Created</h2>
                <p className="text-xs text-slate-400">Your secure link is ready for delivery.</p>
              </div>

              <div className="space-y-4">
                <div className="bg-black/40 p-3 rounded-lg border border-white/5 flex items-center gap-3">
                  <div className="flex-1 overflow-hidden">
                    <p className="text-[10px] font-mono text-slate-500 uppercase mb-1">Vault URI</p>
                    <p className="text-xs font-mono text-blue-400 truncate">{generatedLink}</p>
                  </div>
                  <button 
                    onClick={() => copyToClipboard(generatedLink)}
                    className="p-2 hover:bg-white/5 rounded-md text-slate-400 hover:text-white transition-colors"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>

                <div className="p-4 bg-yellow-500/5 border border-yellow-500/20 rounded-lg flex items-start gap-3">
                  <AlertCircle className="w-4 h-4 text-yellow-500 shrink-0 mt-0.5" />
                  <p className="text-[10px] text-yellow-500/80 leading-relaxed font-medium">
                    <span className="font-bold text-yellow-500 block mb-1">WARNING</span>
                    Anyone with this link can decrypt the file. Do not lose the link, as the decryption key is only stored within the link itself. If you lose it, the data is unrecoverable.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3 mt-6">
                  <button 
                    onClick={reset}
                    className="py-3 text-[10px] font-mono font-bold tracking-wider uppercase bg-white/5 hover:bg-white/10 rounded-lg transition-colors border border-white/10"
                  >
                    Create New
                  </button>
                  <button 
                    onClick={() => copyToClipboard(generatedLink)}
                    className="py-3 text-[10px] font-mono font-bold tracking-wider uppercase bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors flex items-center justify-center gap-2"
                  >
                    <Copy className="w-3 h-3" />
                    Copy Link
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {/* Download View */}
          {view === 'download' && (
            <motion.div 
              key="download"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-[#151619] p-6 rounded-xl technical-border"
            >
              <h2 className="text-lg font-mono font-bold flex items-center gap-2 mb-6">
                <Unlock className="w-4 h-4 text-blue-500" />
                SECURE ACCESS
              </h2>

              {error ? (
                <div className="flex flex-col items-center text-center p-8 bg-red-500/5 border border-red-500/10 rounded-xl">
                  <AlertCircle className="w-12 h-12 text-red-500/30 mb-4" />
                  <h3 className="text-red-400 font-bold mb-2">ACCESS DENIED</h3>
                  <p className="text-xs text-slate-500 mb-6">{error}</p>
                  <button onClick={reset} className="text-xs font-mono uppercase text-slate-400 hover:text-white underline underline-offset-4">Return Home</button>
                </div>
              ) : !targetShare ? (
                <div className="flex flex-col items-center py-12">
                  <Loader2 className="w-8 h-8 animate-spin text-blue-500/30" />
                  <p className="mt-4 text-xs font-mono text-slate-500 uppercase tracking-widest">Verifying Handshake...</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="flex items-center gap-4 bg-black/30 p-4 rounded-xl border border-white/5">
                    {getFileIcon(targetShare.mimeType)}
                    <div className="flex-1 overflow-hidden">
                      <p className="text-sm font-bold text-white truncate">{targetShare.fileName}</p>
                      <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500 uppercase mt-1">
                        <span>{formatSize(targetShare.size)}</span>
                        <span>•</span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3 text-blue-500/50" />
                          <Countdown expiresAt={targetShare.expiresAt} />
                        </span>
                      </div>
                    </div>
                  </div>

                  <button
                    disabled={isDecrypting}
                    onClick={handleDownload}
                    className={`w-full relative py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-mono font-bold uppercase tracking-wider text-xs transition-all flex items-center justify-center gap-2 disabled:opacity-50
                      ${isDecrypting ? 'shadow-[0_0_20px_rgba(59,130,246,0.25)]' : 'shadow-lg'}
                    `}
                  >
                    {isDecrypting ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" />
                        Decrypting...
                      </>
                    ) : (
                      <>
                        <Download className="w-4 h-4" />
                        Decrypt & Open
                      </>
                    )}
                  </button>

                  <div className="p-4 bg-blue-500/5 rounded-lg border border-blue-500/10 flex items-start gap-3">
                    <Shield className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <p className="text-[10px] text-blue-400/80 leading-relaxed italic">
                      This file was decrypted locally in your browser range. The server only provided the encrypted blob; the key was extracted from your private URL fragment.
                    </p>
                  </div>
                </div>
              )}
            </motion.div>
          )}

        </AnimatePresence>
        
        {/* Footer info */}
        <footer className="mt-16 mb-8 flex flex-col items-center gap-6">
          <div className="flex flex-col items-center gap-1.5 group">
            <span className="text-[8px] font-mono text-slate-600 uppercase tracking-[0.4em] opacity-50 group-hover:opacity-100 transition-opacity">Designed & Developed by</span>
            <div className="flex items-center gap-3">
              <div className="h-[1px] w-4 bg-gradient-to-r from-transparent to-slate-800" />
              <span className="text-sm font-mono font-black text-slate-400 tracking-[0.5em] uppercase hover:text-blue-500 transition-colors cursor-default">GM Studio</span>
              <div className="h-[1px] w-4 bg-gradient-to-l from-transparent to-slate-800" />
            </div>
          </div>

          <p className="text-[10px] font-mono text-slate-700 uppercase tracking-widest flex items-center justify-center gap-2 opacity-60">
            <span>AES-256-GCM</span>
            <span>•</span>
            <span>End-to-End Encrypted</span>
          </p>
        </footer>
      </main>
    </div>
  );
}
