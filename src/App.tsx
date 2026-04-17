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
  Terminal,
  Eye,
  ExternalLink,
  X,
  Bell,
  User as UserIcon,
  Search,
  Send,
  Mail,
  AtSign,
  ChevronRight
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
  onSnapshot,
  orderBy,
  limit,
  serverTimestamp, 
  Timestamp
} from 'firebase/firestore';
import { auth, db, signIn, signOut } from './firebase';
import { onAuthStateChanged, User } from 'firebase/auth';
import { encryptData, decryptData, arrayBufferToBase64, base64ToArrayBuffer, generateId } from './lib/crypto';
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
  recipientIds?: string[];
  isMessage?: boolean;
}

interface UserProfile {
  uid: string;
  username: string;
  displayName: string;
  email: string;
  createdAt: any;
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

// --- Helper Components ---

function MessageModal({ text, onClose }: { text: string; onClose: () => void }) {
  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/95 backdrop-blur-md"
    >
      <div className="relative w-full max-w-lg bg-[#151619] rounded-2xl border border-blue-500/20 shadow-[0_0_50px_rgba(59,130,246,0.15)] technical-border overflow-hidden">
        <div className="scanning scanline opacity-30" />
        
        <div className="p-4 border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-2 text-blue-400 font-mono text-[10px] uppercase font-bold tracking-[0.2em]">
            <Mail className="w-3 h-3" />
            Decrypted Stream
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 hover:bg-white/5 rounded-md text-slate-500 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-8">
          <div className="bg-black/30 p-6 rounded-xl border border-white/5 technical-border min-h-[150px] flex items-center justify-center">
            <p className="text-sm font-mono text-white leading-relaxed text-center whitespace-pre-wrap">
              {text}
            </p>
          </div>
        </div>

        <div className="p-4 bg-blue-500/5 border-t border-white/5 flex items-center justify-center gap-4">
          <div className="flex items-center gap-1.5">
            <Shield className="w-3 h-3 text-blue-500/50" />
            <span className="text-[8px] font-mono text-slate-500 uppercase tracking-widest">End-to-End Encrypted</span>
          </div>
          <div className="h-3 w-[1px] bg-white/10" />
          <div className="flex items-center gap-1.5">
            <Lock className="w-3 h-3 text-blue-500/50" />
            <span className="text-[8px] font-mono text-slate-500 uppercase tracking-widest">Zero-Knowledge</span>
          </div>
        </div>

        <button 
          onClick={onClose}
          className="w-full py-4 bg-white/5 hover:bg-white/10 text-white font-mono text-[10px] font-bold uppercase tracking-[0.3em] transition-all border-t border-white/5"
        >
          Close Secure Session
        </button>
      </div>
    </motion.div>
  );
}

function QuantumChatPanel({ 
  onClose, 
  partners, 
  activePartnerUID, 
  activePartnerName,
  setActivePartner, 
  messages, 
  onSendMessage,
  currentUserUID
}: { 
  onClose: () => void; 
  partners: any[]; 
  activePartnerUID: string | null;
  activePartnerName: string | null;
  setActivePartner: (uid: string | null, name: string | null) => void;
  messages: any[];
  onSendMessage: (text: string) => Promise<void>;
  currentUserUID: string;
}) {
  const [searchText, setSearchText] = useState('');
  const [msgInput, setMsgInput] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [searchResult, setSearchResult] = useState<{uid: string, username: string} | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSearch = async () => {
    if (!searchText) return;
    const target = searchText.toLowerCase().trim();
    const snap = await getDoc(doc(db, 'usernames', target));
    if (snap.exists()) {
      setSearchResult({ uid: snap.data().uid, username: target });
    } else {
      setSearchResult(null);
    }
  };

  const handleSend = async () => {
    if (!msgInput) return;
    setIsSending(true);
    await onSendMessage(msgInput);
    setMsgInput('');
    setIsSending(false);
  };

  return (
    <motion.div 
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 25, stiffness: 200 }}
      className="fixed inset-y-0 right-0 z-[60] w-full max-w-md bg-[#0d0e10] border-l border-white/5 shadow-2xl flex flex-col overflow-hidden"
    >
      <div className="absolute inset-0 bg-blue-500/2 opacity-[0.02] pointer-events-none" />
      
      {/* Header */}
      <div className="p-4 border-b border-white/5 flex items-center justify-between bg-black/40 z-10">
        <div className="flex items-center gap-2">
          {activePartnerUID ? (
            <button onClick={() => setActivePartner(null, null)} className="p-2 hover:bg-white/5 rounded-lg text-slate-500 hover:text-white mr-1">
              <Shield className="w-4 h-4" />
            </button>
          ) : (
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Mail className="w-4 h-4 text-blue-500" />
            </div>
          )}
          <div>
            <h2 className="text-xs font-mono font-bold text-white uppercase tracking-widest">
              {activePartnerName ? `@${activePartnerName}` : 'Quantum Chat'}
            </h2>
            <p className="text-[8px] font-mono text-slate-600 uppercase tracking-tighter mt-0.5">
              {activePartnerUID ? 'Secure Relay Active' : 'Select encrypted node'}
            </p>
          </div>
        </div>
        <button onClick={onClose} className="p-2 hover:bg-white/5 rounded-lg text-slate-500 hover:text-white transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>

      {!activePartnerUID ? (
        <div className="flex-1 overflow-hidden flex flex-col z-10">
          <div className="p-4 space-y-4">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-600" />
                <input 
                  type="text"
                  placeholder="Search secure handle..."
                  value={searchText}
                  onChange={(e) => setSearchText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  className="w-full bg-black/40 border border-white/5 rounded-lg py-2.5 pl-9 pr-3 text-[10px] font-mono text-white placeholder:text-slate-800 focus:border-blue-500/30 outline-none transition-all"
                />
              </div>
              <button 
                onClick={handleSearch}
                className="p-2.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg border border-blue-500/20 transition-all"
              >
                <Search className="w-4 h-4" />
              </button>
            </div>

            {searchResult && (
              <motion.button 
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                onClick={() => {
                  setActivePartner(searchResult.uid, searchResult.username);
                  setSearchResult(null);
                  setSearchText('');
                }}
                className="w-full p-4 bg-blue-500/5 border border-blue-500/20 rounded-xl text-left flex items-center justify-between group technical-border"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center text-blue-400 font-mono text-xs font-black">
                    {searchResult.username[0].toUpperCase()}
                  </div>
                  <div>
                    <p className="text-[10px] font-mono font-bold text-white uppercase">@{searchResult.username}</p>
                    <p className="text-[8px] font-mono text-blue-500 uppercase tracking-widest">New Session Available</p>
                  </div>
                </div>
                <Send className="w-3 h-3 text-blue-500 opacity-0 group-hover:opacity-100 transition-opacity" />
              </motion.button>
            )}
          </div>

          <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-2 custom-scrollbar">
            <h3 className="text-[8px] font-mono text-slate-600 uppercase tracking-[0.3em] font-bold px-2 mb-3 mt-4 opacity-50">Active Transmissions</h3>
            {partners.length === 0 ? (
              <div className="py-24 text-center space-y-4">
                <div className="relative inline-block">
                  <Lock className="w-8 h-8 text-slate-800 mx-auto" />
                  <div className="absolute inset-0 animate-ping bg-blue-500/5 rounded-full" />
                </div>
                <p className="text-[10px] font-mono text-slate-700 uppercase tracking-[0.3em] leading-loose">
                  No active secure nodes<br/>detected in range.
                </p>
              </div>
            ) : (
              partners.map(p => (
                <button
                  key={p.uid}
                  onClick={() => setActivePartner(p.uid, p.username)}
                  className="w-full p-4 bg-white/5 hover:bg-white/10 rounded-xl border border-white/5 technical-border text-left group transition-all mb-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-blue-500/5 flex items-center justify-center border border-white/5 text-blue-500/50 text-xs font-mono font-black group-hover:border-blue-500/30 group-hover:text-blue-400 transition-all">
                        {p.username[0].toUpperCase()}
                      </div>
                      <div>
                        <p className="text-[10px] font-mono font-bold text-white uppercase tracking-widest">@{p.username}</p>
                        <p className="text-[8px] font-mono text-slate-600 mt-1 uppercase">Relay Handshake Active</p>
                      </div>
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col overflow-hidden bg-black/20 z-10">
          <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-6 custom-scrollbar">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-8 opacity-30">
                <div className="scanning scanline !h-20 !w-20 !top-1/2 !left-1/2 !-translate-x-1/2 !-translate-y-1/2 opacity-20" />
                <Mail className="w-8 h-8 mb-4 " />
                <p className="text-[10px] font-mono uppercase tracking-[0.3em]">Transmission log empty.</p>
                <p className="text-[8px] font-mono mt-2 tracking-tighter opacity-50 uppercase">All previous secure packets have<br/>undergone self-destruction.</p>
              </div>
            ) : (
              messages.map(m => (
                <div key={m.id} className={`flex ${m.senderId === currentUserUID ? 'justify-end pl-12' : 'justify-start pr-12'}`}>
                  <div className={`relative max-w-full rounded-2xl p-4 text-[11px] font-mono leading-relaxed technical-border ${
                    m.senderId === currentUserUID 
                      ? 'bg-blue-600/10 text-blue-100 border-blue-500/30 rounded-tr-none' 
                      : 'bg-[#1a1b1e] text-slate-200 border-white/5 rounded-tl-none'
                  }`}>
                    <p className="whitespace-pre-wrap">{m.text}</p>
                    <div className="flex items-center justify-between mt-3 gap-4 opacity-30">
                       <span className="text-[7px] uppercase tracking-tighter decoration-blue-500/50">Zero-Knowledge Relay</span>
                       <span className="text-[7px] uppercase tracking-tighter">
                        {new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="p-4 bg-black/40 border-t border-white/5">
            <div className="flex gap-2">
              <input 
                type="text"
                placeholder="Type secure message..."
                value={msgInput}
                onChange={(e) => setMsgInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                className="flex-1 bg-black/40 border border-white/5 rounded-lg px-4 py-3.5 text-[10px] font-mono text-white placeholder:text-slate-800 focus:border-blue-500/30 outline-none transition-all"
              />
              <button 
                onClick={handleSend}
                disabled={isSending || !msgInput}
                className="px-5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:bg-white/5 rounded-lg text-white transition-all shadow-lg shadow-blue-500/10 flex items-center justify-center"
              >
                {isSending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-[7px] font-mono text-slate-700 mt-4 text-center uppercase tracking-[0.3em] flex items-center justify-center gap-3 opacity-60">
              <Shield className="w-2.5 h-2.5" />
              AES-256-GCM locally encrypted packets
            </p>
          </div>
        </div>
      )}
    </motion.div>
  );
}

function PreviewModal({ file, onClose }: { file: { url: string; name: string; type: string }; onClose: () => void }) {
  const isImage = file.type.startsWith('image/');
  const isVideo = file.type.startsWith('video/');
  const isPdf = file.type === 'application/pdf';

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-sm"
    >
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col items-center">
        <div className="absolute -top-12 right-0 flex items-center gap-4">
          <a 
            href={file.url} 
            download={file.name}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-mono text-[10px] uppercase tracking-widest transition-all"
          >
            <Download className="w-3 h-3" />
            Download
          </a>
          <button 
            onClick={onClose}
            className="p-2 bg-white/10 hover:bg-white/20 rounded-full text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="w-full h-full bg-black/40 rounded-2xl border border-white/5 overflow-hidden flex items-center justify-center technical-border">
          {isImage ? (
            <img src={file.url} alt={file.name} className="max-w-full max-h-full object-contain" referrerPolicy="no-referrer" />
          ) : isVideo ? (
            <video src={file.url} controls className="max-w-full max-h-full" />
          ) : isPdf ? (
            <iframe src={file.url} className="w-full h-full min-h-[70vh] border-none" />
          ) : (
            <div className="p-12 text-center">
              <FileText className="w-16 h-16 text-slate-700 mx-auto mb-4" />
              <p className="text-sm font-mono text-slate-500 uppercase tracking-widest">Preview not supported for this file type.</p>
              <p className="text-[10px] text-slate-600 mt-2">Please use the download option instead.</p>
            </div>
          )}
        </div>
        
        <div className="mt-4 flex flex-col items-center gap-1">
          <p className="text-xs font-mono font-bold text-white tracking-widest uppercase truncate max-w-full px-4">{file.name}</p>
          <div className="flex items-center gap-2 text-[8px] font-mono text-slate-500 uppercase tracking-tighter">
            <Shield className="w-3 h-3 text-blue-500/50" />
            Decrypted Zero-Knowledge Stream
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function Countdown({ expiresAt, onExpire }: { expiresAt: any; onExpire?: () => void }) {
  const [timeLeft, setTimeLeft] = useState<string>('...');

  useEffect(() => {
    const target = expiresAt instanceof Timestamp ? expiresAt.toDate() : new Date(expiresAt);
    
    const updateTimer = () => {
      const now = new Date();
      const diff = target.getTime() - now.getTime();
      
      if (diff <= 0) {
        setTimeLeft('EXPIRED');
        if (onExpire) onExpire();
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
  }, [expiresAt, onExpire]);

  return <span>{timeLeft}</span>;
}

// --- Components ---

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [shareId, setShareId] = useState<string | null>(null);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [view, setView] = useState<'home' | 'upload' | 'download' | 'success' | 'setup-profile'>('home');
  const [error, setError] = useState<string | null>(null);
  
  // User Profile & Social
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [inboxCount, setInboxCount] = useState(0);
  const [showInbox, setShowInbox] = useState(false);
  const [inboxShares, setInboxShares] = useState<ShareData[]>([]);
  
  // Home/Receive State
  const [manualLink, setManualLink] = useState('');
  const [messageText, setMessageText] = useState('');
  const [isSendingMessage, setIsSendingMessage] = useState(false);
  const [messageRecipient, setMessageRecipient] = useState('');
  const [activeChatUID, setActiveChatUID] = useState<string | null>(null);
  const [activeChatName, setActiveChatName] = useState<string | null>(null);
  const [chatMessages, setChatMessages] = useState<any[]>([]);
  const [chatPartners, setChatPartners] = useState<any[]>([]);
  const [showChatPanel, setShowChatPanel] = useState(false);
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
  const [decryptedFile, setDecryptedFile] = useState<{ url: string; name: string; type: string } | null>(null);
  const [decryptedMessage, setDecryptedMessage] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
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
        const keysSnap = await getDocs(collection(db, 'shares', id, 'keys'));
        
        const batch = writeBatch(db);
        chunksSnap.forEach(chk => batch.delete(chk.ref));
        keysSnap.forEach(k => batch.delete(k.ref));
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
    if (!user || view === 'setup-profile') return;

    // Listen to direct shares
    const sharesRef = collection(db, 'shares');
    const q = query(
      sharesRef, 
      where('recipientIds', 'array-contains', user.uid),
      limit(20)
    );

    const unsub = onSnapshot(q, (snapshot) => {
      const shares = snapshot.docs
        .map(d => ({ id: d.id, ...d.data() } as ShareData))
        .sort((a, b) => {
          const t1 = (a.createdAt && a.createdAt instanceof Timestamp) ? a.createdAt.toMillis() : Date.now();
          const t2 = (b.createdAt && b.createdAt instanceof Timestamp) ? b.createdAt.toMillis() : Date.now();
          return t2 - t1;
        });
      setInboxShares(shares);
      setInboxCount(shares.length);
    }, (err) => {
      console.error("Inbox listener failed:", err);
    });

    return () => unsub();
  }, [user, view]);

  useEffect(() => {
    if (!user || !showChatPanel) return;

    const sharesRef = collection(db, 'shares');
    const qSent = query(sharesRef, where('ownerId', '==', user.uid), where('isMessage', '==', true));
    const qRec = query(sharesRef, where('recipientIds', 'array-contains', user.uid), where('isMessage', '==', true));

    let sentDocs: any[] = [];
    let recDocs: any[] = [];

    const syncPartners = async () => {
      const combined = [...sentDocs, ...recDocs];
      const pMap = new Map();
      combined.forEach(d => {
        const data = d.data() as ShareData;
        const pid = data.ownerId === user.uid ? data.recipientIds?.[0] : data.ownerId;
        if (pid) pMap.set(pid, true);
      });

      if (pMap.size === 0) {
        setChatPartners([]);
        return;
      }

      const list = await Promise.all(Array.from(pMap.keys()).map(async (pid) => {
        const uSnap = await getDoc(doc(db, 'users', pid));
        return { uid: pid, username: uSnap.data()?.username || 'Anonymous' };
      }));
      setChatPartners(list.filter(p => p.uid !== user.uid));
    };

    const unsub1 = onSnapshot(qSent, (snap) => {
      sentDocs = snap.docs;
      syncPartners();
    });
    const unsub2 = onSnapshot(qRec, (snap) => {
      recDocs = snap.docs;
      syncPartners();
    });

    return () => { unsub1(); unsub2(); };
  }, [user, showChatPanel]);

  useEffect(() => {
    if (!user || !activeChatUID || !showChatPanel) {
      setChatMessages([]);
      return;
    }

    const sharesRef = collection(db, 'shares');
    const qSent = query(sharesRef, where('ownerId', '==', user.uid), where('isMessage', '==', true));
    const qRec = query(sharesRef, where('recipientIds', 'array-contains', user.uid), where('isMessage', '==', true));

    const messageCache = new Map();

    const decryptMessages = async (docs: any[]) => {
      for (const d of docs) {
        const data = { id: d.id, ...d.data() } as ShareData;
        const partnerId = data.ownerId === user.uid ? data.recipientIds?.[0] : data.ownerId;
        
        if (partnerId !== activeChatUID) continue;
        if (messageCache.has(data.id)) continue;

        try {
          const keySnap = await getDoc(doc(db, 'shares', data.id, 'keys', user.uid));
          if (keySnap.exists()) {
            const key = keySnap.data()?.key;
            const chunksSnap = await getDocs(collection(db, 'shares', data.id, 'chunks'));
            const chunkData = chunksSnap.docs[0].data();
            const encryptedBuffer = base64ToArrayBuffer(chunkData.data);
            const decryptedBuffer = await decryptData(encryptedBuffer, data.iv, key);
            const dec = new TextDecoder();
            messageCache.set(data.id, {
              id: data.id,
              text: dec.decode(decryptedBuffer),
              senderId: data.ownerId,
              createdAt: data.createdAt?.toMillis() || Date.now()
            });
          }
        } catch (e) {
          console.error("Chat dec err:", e);
        }
      }
      setChatMessages(Array.from(messageCache.values()).sort((a, b) => a.createdAt - b.createdAt));
    };

    const unsub1 = onSnapshot(qSent, (snap) => decryptMessages(snap.docs));
    const unsub2 = onSnapshot(qRec, (snap) => decryptMessages(snap.docs));

    return () => { unsub1(); unsub2(); };
  }, [user, activeChatUID, showChatPanel]);

  useEffect(() => {
    // Proactive maintenance
    if (isAdmin && view === 'home') {
      pruneExpired();
    }
  }, [isAdmin, view]);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (u) => {
      setUser(u);
      if (u) {
        checkProfile(u.uid);
      } else {
        setProfile(null);
        setLoading(false);
      }
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

  const checkProfile = async (uid: string) => {
    try {
      const docSnap = await getDoc(doc(db, 'users', uid));
      if (docSnap.exists()) {
        setProfile(docSnap.data() as UserProfile);
      } else {
        setView('setup-profile');
      }
    } catch (err) {
      console.error("Profile check failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const saveProfile = async (username: string) => {
    if (!user) return;
    try {
      const uname = username.toLowerCase().trim();
      // Check uniqueness
      const unameRef = doc(db, 'usernames', uname);
      const unameSnap = await getDoc(unameRef);
      if (unameSnap.exists()) {
        throw new Error("Username already taken. Please try another.");
      }

      const batch = writeBatch(db);
      const profileData: UserProfile = {
        uid: user.uid,
        username: uname,
        displayName: user.displayName || uname,
        email: user.email || '',
        createdAt: serverTimestamp()
      };
      batch.set(doc(db, 'users', user.uid), profileData);
      batch.set(unameRef, { uid: user.uid });
      await batch.commit();
      
      setProfile(profileData);
      setView('home');
    } catch (err: any) {
      setError(err.message || "Failed to create profile.");
    }
  };

  const handleSignIn = async () => {
    try {
      setError(null);
      await signIn();
    } catch (err: any) {
      console.error("Sign-in failed:", err);
      if (err.code === 'auth/unauthorized-domain') {
        setError("Domain Unauthorized: Please add your Netlify URL to the 'Authorized Domains' list in Firebase Console.");
      } else if (err.code === 'auth/popup-blocked') {
        setError("Popup Blocked: Please enable popups for this site to sign in.");
      } else {
        setError(err.message || "An error occurred during sign-in.");
      }
    }
  };

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
          
          // Lazy Deletion: Clean up chunks, keys, and metadata
          try {
            const chunksSnap = await getDocs(collection(db, 'shares', id, 'chunks'));
            const keysSnap = await getDocs(collection(db, 'shares', id, 'keys'));
            const batch = writeBatch(db);
            chunksSnap.forEach(chk => batch.delete(chk.ref));
            keysSnap.forEach(k => batch.delete(k.ref));
            batch.delete(docRef);
            await batch.commit();
            console.log("[LAZY DELETE] Expired resource purged on access attempt.");
          } catch (e) {
            console.warn("Lazy cleanup failed, resource may already be gone.");
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
        expiresAt: Timestamp.fromDate(expiresAt),
        recipientIds: []
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
      setShareId(id);
      setSecretKey(key);
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

  const processSecureFile = async (): Promise<{ url: string; name: string; type: string } | null> => {
    if (!targetShare || !secretKey) return null;

    // Real-time Expiry Verification (Prevents access if tab remains open)
    const expiresAt = targetShare.expiresAt instanceof Timestamp ? targetShare.expiresAt.toDate() : new Date(targetShare.expiresAt);
    if (expiresAt < new Date()) {
      setError('Access Denied: This secure link has reached its expiration limit and self-destructed.');
      setTargetShare(null);
      return null;
    }

    try {
      setIsDecrypting(true);
      setCurrentPhase("Verifying link integrity...");
      
      // Double check server-side meta existence
      const docSnap = await getDoc(doc(db, 'shares', targetShare.id));
      if (!docSnap.exists()) {
        throw new Error("Secure vault not found. It may have been purged or deleted.");
      }

      setCurrentPhase("Downloading encrypted packets...");
      
      const chunksSnap = await getDocs(collection(db, 'shares', targetShare.id, 'chunks'));
      const chunksData = chunksSnap.docs
        .map(doc => doc.data() as ChunkData)
        .sort((a, b) => a.index - b.index);

      if (chunksData.length === 0) throw new Error("File parts missing or self-destructed.");

      setCurrentPhase("Reassembling file...");
      
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

      const type = targetShare.mimeType || 'application/octet-stream';
      const blob = new Blob([decryptedBuffer], { type });
      const url = URL.createObjectURL(blob);
      const fileInfo = { url, name: targetShare.fileName, type };
      
      setDecryptedFile(fileInfo);
      return fileInfo;
    } catch (err) {
      console.error(err);
      setError('Decryption failed. The secret key might be invalid or storage is corrupt.');
      return null;
    } finally {
      setIsDecrypting(false);
      setCurrentPhase(null);
    }
  };

  const handleDownload = async () => {
    const file = await processSecureFile();
    if (file) {
      const a = document.createElement('a');
      a.href = file.url;
      a.download = file.name;
      a.click();
    }
  };

  const handlePreview = async () => {
    const file = await processSecureFile();
    if (file) {
      setShowPreview(true);
    }
  };

  const directShareWithUser = async (targetUsername: string) => {
    if (!profile || !shareId || !secretKey) return;
    try {
      setError(null);
      const uname = targetUsername.toLowerCase().trim();
      const unameSnap = await getDoc(doc(db, 'usernames', uname));
      if (!unameSnap.exists()) throw new Error("Recipient username not found.");
      
      const recipientUid = unameSnap.data()?.uid;
      if (recipientUid === user?.uid) throw new Error("You cannot share with yourself.");

      // Store key for recipient securely (this is restricted to that recipient only in rules)
      const shareRef = doc(db, 'shares', shareId);
      const keyRef = doc(shareRef, 'keys', recipientUid);
      
      const batch = writeBatch(db);
      batch.set(keyRef, { key: secretKey });
      
      // Update share metadata to include recipient in list for indexing
      const shareSnap = await getDoc(shareRef);
      const shareMeta = shareSnap.data() as ShareData;
      const recipients = shareMeta.recipientIds || [];
      if (!recipients.includes(recipientUid)) {
        recipients.push(recipientUid);
        batch.update(shareRef, { recipientIds: recipients });
      }
      
      await batch.commit();
      return true;
    } catch (err: any) {
      setError(err.message);
      return false;
    }
  };

  const sendSecureMessage = async () => {
    if (!profile || !messageRecipient || !messageText) return;
    
    try {
      setIsSendingMessage(true);
      setError(null);

      const targetUname = messageRecipient.toLowerCase().trim();
      const unameSnap = await getDoc(doc(db, 'usernames', targetUname));
      if (!unameSnap.exists()) throw new Error("Recipient handle not found in database.");
      
      const recipientUid = unameSnap.data()?.uid;
      await sendChatMessage(recipientUid, messageText);

      setMessageText('');
      setMessageRecipient('');
      setError(`[SECURE TRANSMISSION COMPLETE] Message relayed to @${targetUname}`);
      setTimeout(() => setError(null), 5000);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Encryption relay failure.");
    } finally {
      setIsSendingMessage(false);
    }
  };

  const sendChatMessage = async (recipientUid: string, text: string) => {
    if (!user || !text || !recipientUid) return;

    try {
      // 1. Local Encryption
      const { encryptedBuffer, iv, key } = await encryptData(text);
      const id = generateId();
      const encryptedBase64 = arrayBufferToBase64(encryptedBuffer!);

      // 2. Prep metadata
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + expiryMinutes);

      const shareObj: ShareData = {
        id,
        iv,
        chunkCount: 1,
        fileName: "Secure Message",
        mimeType: "text/plain",
        size: text.length,
        createdAt: serverTimestamp(),
        expiresAt: Timestamp.fromDate(expiresAt),
        recipientIds: [recipientUid],
        ownerId: user.uid,
        isMessage: true
      };

      const batch = writeBatch(db);
      batch.set(doc(db, 'shares', id), shareObj);
      batch.set(doc(db, 'shares', id, 'chunks', 'm0'), {
        data: encryptedBase64,
        index: 0
      });
      batch.set(doc(db, 'shares', id, 'keys', recipientUid), { key });
      batch.set(doc(db, 'shares', id, 'keys', user.uid), { key });

      await batch.commit();
    } catch (err: any) {
      console.error("Chat send failed:", err);
      throw err;
    }
  };

  const handleInboxItemClick = async (share: ShareData) => {
    try {
      setError(null);
      setLoading(true);
      setShowInbox(false);
      
      // Fetch the secret key specifically for this recipient
      const keySnap = await getDoc(doc(db, 'shares', share.id, 'keys', user!.uid));
      if (!keySnap.exists()) throw new Error("Decryption key was not found or has been revoked.");
      
      const key = keySnap.data()?.key;
      setSecretKey(key);
      setShareId(share.id);
      setTargetShare(share);

      if (share.isMessage) {
        // Auto-decrypt message using existing helpers
        setIsDecrypting(true);
        const chunksSnap = await getDocs(collection(db, 'shares', share.id, 'chunks'));
        const chunkData = chunksSnap.docs[0].data();
        
        const encryptedBuffer = base64ToArrayBuffer(chunkData.data);
        const decryptedBuffer = await decryptData(encryptedBuffer, share.iv, key);
        
        const dec = new TextDecoder();
        setDecryptedMessage(dec.decode(decryptedBuffer));
        setIsDecrypting(false);
      } else {
        setView('download');
      }
      
      setLoading(false);
    } catch (err: any) {
      setLoading(false);
      setError(err.message);
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
          {user && profile && (
            <button 
              onClick={() => setShowInbox(!showInbox)}
              className="relative p-2 bg-white/5 hover:bg-white/10 rounded-lg technical-border transition-all"
            >
              <Bell className={`w-5 h-5 ${inboxCount > 0 ? 'text-blue-500 animate-pulse' : 'text-slate-500'}`} />
              {inboxCount > 0 && (
                <span className="absolute -top-1 -right-1 w-4 h-4 bg-blue-600 text-[10px] font-bold rounded-full flex items-center justify-center text-white border-2 border-[#0d0e10]">
                  {inboxCount}
                </span>
              )}
            </button>
          )}

          {user ? (
            <div className="flex items-center gap-3">
              <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                <UserIcon className="w-3 h-3 text-blue-500 glow-blue" />
                <span className="text-xs font-mono font-bold text-blue-400 uppercase tracking-tighter">
                  {profile?.username ? `@${profile.username}` : user.email}
                </span>
              </div>
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
              onClick={handleSignIn}
              className="text-xs font-mono uppercase tracking-wider bg-white/5 hover:bg-white/10 px-4 py-2 rounded-md border border-white/10 transition-all"
            >
              Sign In
            </button>
          )}
        </div>
      </nav>

      <main className="max-w-md mx-auto relative cursor-default">
        <AnimatePresence mode="wait">
          
          {/* Inbox Overlay */}
          <AnimatePresence>
            {showInbox && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="fixed top-20 right-4 w-80 max-h-[70vh] bg-[#151619] border border-white/5 rounded-2xl shadow-2xl z-40 overflow-hidden flex flex-col"
              >
                <div className="p-4 border-bottom border-white/5 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Bell className="w-4 h-4 text-blue-500" />
                    <span className="text-xs font-mono font-bold uppercase tracking-widest text-white">Secure Inbox</span>
                  </div>
                  <button onClick={() => setShowInbox(false)} className="text-slate-500 hover:text-white"><X className="w-4 h-4" /></button>
                </div>
                
                <div className="flex-1 overflow-y-auto p-2 space-y-2">
                  {inboxShares.length === 0 ? (
                    <div className="py-12 text-center">
                      <Shield className="w-8 h-8 text-slate-800 mx-auto mb-3" />
                      <p className="text-[10px] font-mono text-slate-600 uppercase tracking-widest">No direct fragments found.</p>
                    </div>
                  ) : (
                    inboxShares.map(share => (
                      <button
                        key={share.id}
                        onClick={() => handleInboxItemClick(share)}
                        className="w-full p-3 bg-white/5 hover:bg-white/10 rounded-xl technical-border text-left transition-all group"
                      >
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg ${share.isMessage ? 'bg-purple-500/10' : 'bg-blue-500/10'}`}>
                            {share.isMessage ? (
                              <Mail className="w-4 h-4 text-purple-400" />
                            ) : (
                              getFileIcon(share.mimeType)
                            )}
                          </div>
                          <div className="flex-1 overflow-hidden">
                            <p className={`text-[10px] font-bold truncate group-hover:text-blue-400 transition-colors uppercase ${share.isMessage ? 'text-purple-400' : 'text-white'}`}>
                              {share.isMessage ? 'Secure Message' : share.fileName}
                            </p>
                            <p className="text-[8px] font-mono text-slate-500 mt-1 uppercase">
                              {share.isMessage ? 'Encrypted Text' : formatSize(share.size)} • <Countdown expiresAt={share.expiresAt} />
                            </p>
                          </div>
                          {share.isMessage ? (
                            <Mail className="w-3 h-3 text-slate-700 group-hover:text-purple-500 transition-colors" />
                          ) : (
                            <Download className="w-3 h-3 text-slate-700 group-hover:text-blue-500 transition-colors" />
                          )}
                        </div>
                      </button>
                    ))
                  )}
                </div>
                
                <div className="p-3 bg-black/40 border-t border-white/5">
                  <p className="text-[8px] font-mono text-slate-600 text-center uppercase tracking-tighter">
                    Direct shares are stored with secondary keys bound to your identity.
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Setup Profile View */}
          {view === 'setup-profile' && (
            <motion.div 
              key="setup"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="bg-[#151619] p-8 rounded-2xl technical-border flex flex-col items-center text-center shadow-2xl"
            >
              <div className="p-4 bg-blue-500/10 rounded-2xl mb-6 relative">
                <UserIcon className="w-8 h-8 text-blue-500" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-blue-600 rounded-full animate-ping" />
              </div>
              
              <h2 className="text-xl font-mono font-bold text-white mb-2 uppercase tracking-tighter">Initialize Identity</h2>
              <p className="text-xs text-slate-500 mb-8 font-mono leading-relaxed lowercase italic line-clamp-2">
                choose a unique handle to enable direct transfers and secure identity mapping.
              </p>

              <form 
                onSubmit={(e) => {
                  e.preventDefault();
                  const val = (e.currentTarget.elements.namedItem('username') as HTMLInputElement).value;
                  saveProfile(val);
                }}
                className="w-full space-y-4"
              >
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                    <span className="text-blue-500/50 font-mono text-sm group-focus-within:text-blue-500 transition-colors">@</span>
                  </div>
                  <input 
                    name="username"
                    required
                    maxLength={20}
                    minLength={3}
                    placeholder="Enter unique handle..."
                    className="w-full bg-black/40 border border-white/10 focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 rounded-xl py-3 pl-10 pr-4 text-sm font-mono text-white placeholder:text-slate-700 outline-none transition-all"
                  />
                </div>
                
                {error && (
                  <p className="text-[10px] text-red-400 font-mono uppercase tracking-tighter bg-red-500/10 p-2 rounded-lg border border-red-500/20">
                    {error}
                  </p>
                )}

                <button 
                  type="submit"
                  className="w-full py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-mono text-xs font-bold uppercase tracking-widest transition-all shadow-lg shadow-blue-500/10"
                >
                  Create Identity
                </button>
              </form>
            </motion.div>
          )}

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
                  </div>

                    <div className="bg-blue-500/5 p-6 rounded-xl border border-blue-500/10 text-left">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="font-mono font-bold text-lg leading-none uppercase flex items-center gap-2">
                           <Mail className="w-4 h-4 text-blue-400" />
                           Quantum Message
                        </h3>
                        <button 
                          onClick={() => setShowChatPanel(true)}
                          className="px-3 py-1.5 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/20 rounded-lg text-[8px] font-mono font-bold uppercase tracking-widest transition-all flex items-center gap-2"
                        >
                          <Send className="w-3 h-3" />
                          Secure Chats
                        </button>
                      </div>
                    <div className="space-y-3">
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                          <AtSign className="w-3 h-3 text-blue-500/40" />
                        </div>
                        <input 
                          type="text"
                          placeholder="Recipient handle..."
                          value={messageRecipient}
                          onChange={(e) => setMessageRecipient(e.target.value)}
                          className="w-full bg-black/40 border border-white/5 focus:border-blue-500/30 rounded-lg py-2 pl-9 pr-3 text-[10px] font-mono text-white placeholder:text-slate-800 outline-none transition-all"
                        />
                      </div>
                      <textarea 
                        placeholder="Type secure message (Encrypted locally)..."
                        value={messageText}
                        onChange={(e) => setMessageText(e.target.value)}
                        rows={3}
                        className="w-full bg-black/40 border border-white/5 focus:border-blue-500/30 rounded-lg p-3 text-[10px] font-mono text-white placeholder:text-slate-800 outline-none transition-all resize-none"
                      />
                      <button 
                        disabled={isSendingMessage || !messageRecipient || !messageText}
                        onClick={sendSecureMessage}
                        className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-white/5 disabled:text-slate-600 py-3 rounded-lg text-[10px] font-mono font-bold uppercase tracking-widest transition-all flex items-center justify-center gap-2"
                      >
                        {isSendingMessage ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : (
                          <Send className="w-3 h-3" />
                        )}
                        Relay Secure Message
                      </button>
                    </div>
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

                {/* Direct Share Component */}
                <div className="mt-8 pt-8 border-t border-white/5">
                  <div className="flex items-center gap-2 mb-4">
                    <Send className="w-3 h-3 text-blue-500" />
                    <span className="text-[10px] font-mono font-bold text-white uppercase tracking-widest">Direct Share (In-App)</span>
                  </div>
                  <p className="text-[10px] text-slate-500 mb-4 font-mono lowercase">Send this file directly to another CipherVault user's inbox.</p>
                  
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Search className="w-3 h-3 text-slate-700" />
                      </div>
                      <input 
                        id="recipientInput"
                        placeholder="Recipient username..."
                        className="w-full bg-black/40 border border-white/5 focus:border-blue-500/30 rounded-lg py-2 pl-9 pr-3 text-[10px] font-mono text-white placeholder:text-slate-800 outline-none transition-all"
                        onKeyPress={async (e) => {
                          if (e.key === 'Enter') {
                            const input = e.currentTarget;
                            const name = input.value;
                            const success = await directShareWithUser(name);
                            if (success) {
                              input.value = '';
                              setError(`[DIRECT SUCCESS] Securely shared with @${name}`);
                              setTimeout(() => setError(null), 3000);
                            }
                          }
                        }}
                      />
                    </div>
                    <button 
                      onClick={async () => {
                        const input = document.getElementById('recipientInput') as HTMLInputElement;
                        const success = await directShareWithUser(input.value);
                        if (success) {
                          const name = input.value;
                          input.value = '';
                          // No alert in iframe, we use the error state or a temporary success state
                          setError(`[DIRECT SUCCESS] Securely shared with @${name}`);
                          setTimeout(() => setError(null), 3000);
                        }
                      }}
                      className="px-4 bg-white/5 hover:bg-white/10 text-white rounded-lg border border-white/10 transition-all"
                    >
                      <Check className="w-4 h-4" />
                    </button>
                  </div>
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
                          <Countdown 
                            expiresAt={targetShare.expiresAt} 
                            onExpire={() => {
                              setError('This secure share has expired and self-destructed.');
                              setTargetShare(null);
                            }}
                          />
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <button
                      disabled={isDecrypting}
                      onClick={handleDownload}
                      className={`relative py-4 bg-white/5 hover:bg-white/10 text-white rounded-lg font-mono font-bold uppercase tracking-wider text-[10px] transition-all flex items-center justify-center gap-2 disabled:opacity-50 border border-white/10
                        ${isDecrypting ? 'shadow-[0_0_20px_rgba(59,130,246,0.1)]' : ''}
                      `}
                    >
                      {isDecrypting ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <Download className="w-3 h-3" />
                      )}
                      Decrypt & Download
                    </button>

                    <button
                      disabled={isDecrypting}
                      onClick={handlePreview}
                      className={`relative py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-mono font-bold uppercase tracking-wider text-[10px] transition-all flex items-center justify-center gap-2 disabled:opacity-50 shadow-lg
                        ${isDecrypting ? 'shadow-[0_0_20px_rgba(59,130,246,0.25)]' : 'shadow-lg shadow-blue-500/10'}
                      `}
                    >
                      {isDecrypting ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <Eye className="w-3 h-3" />
                      )}
                      Decrypt & View
                    </button>
                  </div>

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
        
        <AnimatePresence>
          {showPreview && decryptedFile && (
            <PreviewModal 
              file={decryptedFile} 
              onClose={() => setShowPreview(false)} 
            />
          )}
          {decryptedMessage && (
            <MessageModal 
              text={decryptedMessage} 
              onClose={() => setDecryptedMessage(null)} 
            />
          )}
          {showChatPanel && user && (
            <QuantumChatPanel 
              onClose={() => setShowChatPanel(false)}
              partners={chatPartners}
              activePartnerUID={activeChatUID}
              activePartnerName={activeChatName}
              setActivePartner={(uid, name) => {
                setActiveChatUID(uid);
                setActiveChatName(name);
              }}
              messages={chatMessages}
              onSendMessage={(text) => sendChatMessage(activeChatUID!, text)}
              currentUserUID={user.uid}
            />
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
