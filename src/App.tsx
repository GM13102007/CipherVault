/**
 * CipherVault: Zero-Knowledge Secure File Sharing
 * Client-side AES-256-GCM encryption
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
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
  ChevronRight,
  ChevronLeft,
  Activity,
  Wifi,
  Zap,
  Sun,
  Moon,
  Monitor,
  Key,
  Hash,
  Fingerprint,
  LogOut,
  Edit
} from 'lucide-react';
import { 
  doc, 
  setDoc, 
  getDoc, 
  deleteDoc,
  updateDoc,
  collection,
  getDocs,
  writeBatch,
  query,
  where,
  onSnapshot,
  orderBy,
  limit,
  serverTimestamp, 
  Timestamp,
  arrayUnion,
  arrayRemove,
  or,
  and
} from 'firebase/firestore';
import { auth, db, primaryAuth, primaryDb, backupAuth, backupDb, signInAll, signOutAll } from './firebase';
import { onAuthStateChanged, User, signInWithPopup, GoogleAuthProvider } from 'firebase/auth';
import { supabase, isSupabaseReady } from './supabase';
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
  senderHandle?: string;
}

interface UserProfile {
  uid: string;
  username: string;
  displayName: string;
  email: string;
  createdAt: any;
  privateKeys?: string[];
}

interface ChunkData {
  data: string;
  index: number;
}

// --- Helper Components ---

function AdminDashboard({ onPrune, quotaExceeded }: { onPrune: () => Promise<void>; quotaExceeded?: boolean }) {
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
        disabled={loading || quotaExceeded}
        className="w-full py-2 bg-red-600/20 hover:bg-red-600/30 text-red-500 border border-red-500/30 rounded font-mono text-[10px] uppercase font-bold tracking-widest transition-all flex items-center justify-center gap-2 disabled:opacity-50"
      >
        {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : done ? <Check className="w-3 h-3" /> : <Trash2 className="w-3 h-3" />}
        {loading ? 'Pruning Fragments...' : quotaExceeded ? 'Quota Locked' : done ? 'Purge Complete' : 'Execute Global Prune'}
      </button>
    </motion.div>
  );
}

// --- Helper Components ---

function MessageModal({ text, sender, onClose }: { text: string; sender?: string; onClose: () => void }) {
  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-bg-base/90 backdrop-blur-md"
    >
      <div className="relative w-full max-w-lg bg-bg-card rounded-2xl border border-blue-500/20 shadow-2xl technical-border overflow-hidden">
        <div className="scanning scanline opacity-30" />
        
        <div className="p-4 border-b border-border-main flex items-center justify-between">
          <div className="flex items-center gap-2 text-blue-400 font-mono text-[10px] uppercase font-bold tracking-[0.2em]">
            <Mail className="w-3 h-3" />
            Decrypted Stream
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 hover:bg-black/5 rounded-md text-text-sub hover:text-text-main transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {sender && (
          <div className="px-8 pt-6 flex justify-center">
            <div className="px-3 py-1 bg-blue-500/10 border border-blue-500/20 rounded-full flex items-center gap-2">
              <UserIcon className="w-3 h-3 text-blue-400" />
              <span className="text-[9px] font-mono font-bold text-blue-400 uppercase tracking-widest">Relayed by @{sender}</span>
            </div>
          </div>
        )}

        <div className="p-8">
          <div className="bg-bg-base/40 p-6 rounded-xl border border-border-main technical-border min-h-[150px] flex items-center justify-center">
            <p className="text-sm font-mono text-text-main leading-relaxed text-center whitespace-pre-wrap">
              {text}
            </p>
          </div>
        </div>

        <div className="p-4 bg-blue-500/5 border-t border-border-main flex items-center justify-center gap-4">
          <div className="flex items-center gap-1.5">
            <Shield className="w-3 h-3 text-blue-500/50" />
            <span className="text-[8px] font-mono text-text-sub uppercase tracking-widest">End-to-End Encrypted</span>
          </div>
          <div className="h-3 w-[1px] bg-border-main" />
          <div className="flex items-center gap-1.5">
            <Lock className="w-3 h-3 text-blue-500/50" />
            <span className="text-[8px] font-mono text-text-sub uppercase tracking-widest">Zero-Knowledge</span>
          </div>
        </div>

        <button 
          onClick={onClose}
          className="w-full py-4 bg-bg-base/5 hover:bg-bg-base/10 text-text-main font-mono text-[10px] font-bold uppercase tracking-[0.3em] transition-all border-t border-border-main"
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
    try {
      const snap = await getDoc(doc(db, 'usernames', target));
      if (snap.exists()) {
        setSearchResult({ uid: snap.data().uid, username: target });
      } else {
        setSearchResult(null);
      }
    } catch (err) {
      console.error(err);
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
      className="fixed inset-y-0 right-0 z-[60] w-full md:max-w-md bg-bg-base border-l border-border-main shadow-[0_0_100px_rgba(0,0,0,0.5)] flex flex-col overflow-hidden font-mono"
    >
      <div className="absolute inset-0 bg-blue-500/5 opacity-[0.03] pointer-events-none bg-[radial-gradient(circle_at_50%_0%,rgba(59,130,246,0.1)_0%,transparent_75%)]" />
      <div className="scanning scanline opacity-10 pointer-events-none" />
      
      {/* Header */}
      <div className="relative p-6 border-b border-border-main bg-bg-base/40 z-10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {activePartnerUID ? (
              <button 
                onClick={() => setActivePartner(null, null)} 
                className="group w-10 h-10 flex items-center justify-center bg-blue-500/10 hover:bg-blue-500/20 rounded-lg technical-border transition-all"
              >
                <AtSign className="w-5 h-5 text-blue-500 group-hover:scale-110 transition-transform" />
              </button>
            ) : (
              <div className="w-10 h-10 flex items-center justify-center bg-blue-500/10 rounded-lg technical-border">
                <Mail className="w-5 h-5 text-blue-500 glow-blue" />
              </div>
            )}
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-black text-text-main uppercase tracking-[0.2em]">
                  {activePartnerName ? `@${activePartnerName}` : 'NODE_INVENTORY'}
                </h2>
                <div className="flex gap-0.5">
                  <div className="w-[2px] h-3 bg-blue-500/60 animate-pulse" />
                  <div className="w-[2px] h-3 bg-blue-500/40" />
                  <div className="w-[2px] h-3 bg-blue-500/20" />
                </div>
              </div>
              <div className="flex items-center gap-2 mt-1">
                <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse glow-green" />
                <span className="text-[8px] text-text-sub uppercase tracking-widest leading-none">
                  {activePartnerUID ? 'Protocol: AES-256-RELAY' : 'SCANNING_SPECTRUM...'}
                </span>
              </div>
            </div>
          </div>
          <button 
            onClick={onClose} 
            className="w-10 h-10 flex items-center justify-center hover:bg-black/5 rounded-full text-text-sub hover:text-text-main transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Technical Hud Line */}
        <div className="absolute bottom-0 left-0 h-[1px] bg-gradient-to-r from-transparent via-blue-500/30 to-transparent w-full" />
      </div>

      {!activePartnerUID ? (
        <div className="flex-1 overflow-hidden flex flex-col z-10">
          <div className="p-6 space-y-6">
            <div className="relative group">
              <div className="absolute inset-0 bg-blue-500/10 blur-xl opacity-0 group-focus-within:opacity-100 transition-opacity" />
              <div className="relative flex gap-2">
                <input 
                  type="text"
                  placeholder="RESOLVE_TARGET_HANDLE..."
                  value={searchText}
                  onChange={(e) => setSearchText(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  className="flex-1 bg-black/60 border border-white/5 rounded-xl py-4 pl-12 pr-4 text-[11px] text-blue-400 placeholder:text-slate-800 focus:border-blue-500/50 outline-none transition-all technical-border"
                />
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-700 group-focus-within:text-blue-500 transition-colors" />
                <button 
                  onClick={handleSearch}
                  className="px-6 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 rounded-xl border border-blue-500/20 font-bold text-[10px] uppercase tracking-widest transition-all active:scale-95"
                >
                  SCAN
                </button>
              </div>
            </div>

            {searchResult && (
              <motion.button 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                onClick={() => {
                  setActivePartner(searchResult.uid, searchResult.username);
                  setSearchResult(null);
                  setSearchText('');
                }}
                className="w-full p-6 bg-blue-500/5 border border-blue-500/20 rounded-2xl text-left flex items-center justify-between group technical-border relative overflow-hidden"
              >
                <div className="scanning scanline opacity-20" />
                <div className="flex items-center gap-4 relative z-10">
                  <div className="w-12 h-12 rounded-xl bg-blue-600/20 flex items-center justify-center text-blue-400 font-black text-lg border border-blue-500/30 group-hover:glow-blue transition-all">
                    {searchResult.username[0].toUpperCase()}
                  </div>
                  <div>
                    <h4 className="text-xs font-black text-white uppercase tracking-widest group-hover:text-blue-400 transition-colors">@{searchResult.username}</h4>
                    <div className="flex items-center gap-2 mt-1.5">
                      <Zap className="w-3 h-3 text-yellow-500 animate-pulse" />
                      <span className="text-[8px] text-slate-500 uppercase tracking-widest">Handshake Ready for initiation</span>
                    </div>
                  </div>
                </div>
                <ChevronRight className="w-4 h-4 text-blue-500 translate-x-0 group-hover:translate-x-1 transition-transform" />
              </motion.button>
            )}
          </div>

          <div className="flex-1 overflow-y-auto px-6 pb-6 space-y-4 custom-scrollbar">
            <div className="flex items-center justify-between opacity-50 px-2 mb-4">
              <span className="text-[9px] font-bold text-slate-600 uppercase tracking-[0.4em]">Active Secure Nodes</span>
              <div className="h-[1px] flex-1 bg-white/5 mx-4" />
              <Activity className="w-3 h-3 text-slate-600" />
            </div>

            {partners.length === 0 ? (
              <div className="py-24 text-center">
                <div className="relative inline-block mb-6">
                  <div className="absolute inset-0 bg-blue-500/20 blur-2xl animate-pulse" />
                  <div className="relative w-16 h-16 rounded-3xl border border-white/5 bg-black/40 flex items-center justify-center">
                    <Wifi className="w-8 h-8 text-slate-800" />
                  </div>
                </div>
                <p className="text-[10px] text-slate-700 uppercase tracking-[0.4em] leading-relaxed">
                  Spectrum analysis complete.<br/>zero active nodes in range.
                </p>
              </div>
            ) : (
              partners.map(p => (
                <button
                  key={p.uid}
                  onClick={() => setActivePartner(p.uid, p.username)}
                  className="w-full p-5 bg-[#151619] hover:bg-[#1a1b1e] rounded-2xl border border-white/5 hover:border-blue-500/20 technical-border text-left group transition-all relative overflow-hidden active:scale-[0.98]"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500/10 to-transparent flex items-center justify-center border border-white/10 text-blue-500/60 font-black group-hover:border-blue-500/50 group-hover:text-blue-400 transition-all">
                        {p.username[0].toUpperCase()}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="text-[11px] font-black text-white uppercase tracking-[0.2em] group-hover:text-blue-400 transition-colors">@{p.username}</h4>
                          <span className="w-1 h-1 rounded-full bg-blue-500 glow-blue animate-pulse" />
                        </div>
                        <div className="flex items-center gap-2 mt-2">
                           <Shield className="w-3 h-3 text-slate-700" />
                           <span className="text-[8px] text-slate-600 uppercase tracking-widest">Connection Stable</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-1 opacity-40 group-hover:opacity-100 transition-opacity">
                      <div className="w-8 h-[2px] bg-white/10" />
                      <div className="w-6 h-[2px] bg-white/10" />
                      <div className="w-4 h-[2px] bg-white/10" />
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col overflow-hidden z-10 bg-black/20">
          {/* Signal Hud */}
          <div className="px-6 py-2 bg-blue-500/5 border-b border-white/5 flex items-center justify-between">
            <div className="flex items-center gap-4">
               <div className="flex items-center gap-1.5">
                  <Wifi className="w-3 h-3 text-blue-500" />
                  <span className="text-[8px] text-blue-400 font-bold uppercase tracking-widest">Strength: 100%</span>
               </div>
               <div className="h-3 w-[1px] bg-white/10" />
               <div className="flex items-center gap-1.5">
                  <Activity className="w-3 h-3 text-green-500" />
                  <span className="text-[8px] text-slate-500 font-bold uppercase tracking-widest">Latency: 12ms</span>
               </div>
            </div>
            <span className="text-[8px] text-slate-600 uppercase tracking-tighter tabular-nums">ID: {activePartnerUID.substring(0, 12)}</span>
          </div>

          <div ref={scrollRef} className="flex-1 overflow-y-auto p-6 space-y-8 custom-scrollbar relative">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-12 opacity-20">
                <div className="relative mb-6">
                  <div className="absolute inset-0 bg-blue-500/10 blur-3xl animate-pulse" />
                  <Mail className="w-12 h-12 relative z-10" />
                </div>
                <p className="text-[10px] uppercase tracking-[0.5em] font-black mb-2">Zero-Knowledge Null</p>
                <p className="text-[8px] tracking-widest uppercase opacity-60 max-w-[200px] leading-relaxed">all previous transmissions have been purged from the active node cache.</p>
              </div>
            ) : (
              messages.map(m => (
                <div key={m.id} className={`flex ${m.senderId === currentUserUID ? 'justify-end pl-12' : 'justify-start pr-12'}`}>
                  <div className={`relative max-w-full rounded-2xl p-5 text-[11px] leading-relaxed technical-border group ${
                    m.senderId === currentUserUID 
                      ? 'bg-blue-600/10 border-blue-500/30 text-blue-50 rounded-tr-none' 
                      : 'bg-bg-card border-border-main text-text-main rounded-tl-none'
                  }`}>
                    <div className={`absolute top-0 ${m.senderId === currentUserUID ? 'right-0 -translate-y-full tracking-[0.3em] text-blue-500/40 text-[7px]' : 'left-0 -translate-y-full tracking-[0.3em] text-slate-600 text-[7px]'} uppercase font-black py-1`}>
                      {m.senderId === currentUserUID ? 'LOCAL_NODE v2.0' : `@${activePartnerName?.toUpperCase()} RELAY`}
                    </div>
                    
                    <p className="whitespace-pre-wrap">{m.text}</p>
                    
                    <div className="flex items-center justify-between mt-4 pt-3 border-t border-white/5 gap-6 opacity-30">
                       <div className="flex items-center gap-2">
                          <Shield className="w-2.5 h-2.5" />
                          <span className="text-[7px] uppercase tracking-[0.2em] font-bold">Secured Packet</span>
                       </div>
                       <span className="text-[8px] uppercase tabular-nums font-bold">
                        {new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="p-6 bg-bg-base/60 border-t border-border-main backdrop-blur-xl relative">
            <div className="absolute top-0 left-0 h-[2px] bg-blue-600/50 w-full animate-pulse-glow" />
            <div className="flex items-end gap-3">
              <div className="flex-1 relative">
                <textarea 
                  placeholder="TRANSMIT_SECURE_PACKET..."
                  value={msgInput}
                  onChange={(e) => setMsgInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleSend();
                    }
                  }}
                  rows={1}
                  className="w-full bg-bg-card/40 border border-border-main rounded-2xl px-5 py-4 text-[11px] text-text-main placeholder:text-text-sub focus:border-blue-500/50 outline-none transition-all resize-none technical-border custom-scrollbar"
                />
              </div>
              <button 
                onClick={handleSend}
                disabled={isSending || !msgInput}
                className="w-14 h-14 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:bg-white/5 rounded-2xl text-white transition-all shadow-[0_0_20px_rgba(59,130,246,0.3)] flex items-center justify-center active:scale-95 group overflow-hidden"
              >
                {isSending ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <div className="relative">
                    <Send className="w-5 h-5 group-hover:scale-110 group-hover:glow-blue transition-all" />
                  </div>
                )}
                <div className="scanning scanline !h-full opacity-30 pointer-events-none" />
              </button>
            </div>
            <div className="mt-4 flex items-center justify-center gap-6">
              <div className="flex items-center gap-2">
                <Lock className="w-2.5 h-2.5 text-slate-800" />
                <span className="text-[7px] text-slate-800 uppercase tracking-[0.4em] font-black">Zero-Knowledge Pipeline</span>
              </div>
              <div className="h-1 w-1 rounded-full bg-slate-800" />
              <div className="flex items-center gap-2">
                <Activity className="w-2.5 h-2.5 text-slate-800" />
                <span className="text-[7px] text-slate-800 uppercase tracking-[0.4em] font-black">Quantum Resiliency: Active</span>
              </div>
            </div>
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

// --- Helpers ---

const generateCustomKey = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  let result = '';
  for (let i = 0; i < 15; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

// --- Components ---

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [shareId, setShareId] = useState<string | null>(null);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [view, setView] = useState<'home' | 'upload' | 'download' | 'success' | 'setup-profile'>('home');
  const [error, setError] = useState<string | null>(null);
  const [quotaExceeded, setQuotaExceeded] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light' | 'system'>(() => {
    return (localStorage.getItem('vault_theme') as any) || 'system';
  });
  
  // User Profile & Social
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [showInbox, setShowInbox] = useState(false);
  const [inboxShares, setInboxShares] = useState<ShareData[]>([]);
  const prevInboxCount = useRef(inboxShares.length);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const decryptedCache = useRef<Map<string, any>>(new Map());
  const [seenMessageIds, setSeenMessageIds] = useState<Set<string>>(() => {
    const saved = localStorage.getItem('seen_fragments');
    return saved ? new Set(JSON.parse(saved)) : new Set();
  });
  
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
  const [showPrivateKeyPanel, setShowPrivateKeyPanel] = useState(false);
  const [entryKey, setEntryKey] = useState('');
  const [isResolvingKey, setIsResolvingKey] = useState(false);
  const [customKeyInput, setCustomKeyInput] = useState('');
  const [editingKeyIndex, setEditingKeyIndex] = useState<number | null>(null);
  const [editValue, setEditValue] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [isBackupActive, setIsBackupActive] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState<string | null>(null);
  const [expiryMinutes, setExpiryMinutes] = useState(5);
  const [generatedLink, setGeneratedLink] = useState('');
  const [currentTime, setCurrentTime] = useState(Date.now());

  // Download State
  const [targetShare, setTargetShare] = useState<ShareData | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedFile, setDecryptedFile] = useState<{ url: string; name: string; type: string } | null>(null);
  const [decryptedMessage, setDecryptedMessage] = useState<{ text: string; sender: string } | null>(null);
  const [targetSenderHandle, setTargetSenderHandle] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [showAdmin, setShowAdmin] = useState(false);
  const maintenancePerformed = useRef(false);

  // --- Maintenance Rules ---
  const isAdmin = user?.email === 'transferd001@gmail.com';

  const pruneExpired = async () => {
    if (maintenancePerformed.current) return;
    maintenancePerformed.current = true;

    const nodes = [primaryDb, backupDb];
    
    for (const node of nodes) {
      try {
        const sharesRef = collection(node, 'shares');
        const q = query(
          sharesRef, 
          where('expiresAt', '<', Timestamp.now()),
          limit(5)
        );
        const snapshot = await getDocs(q);
        
        if (!snapshot.empty) {
          const batch = writeBatch(node);
          for (const shareDoc of snapshot.docs) {
            const id = shareDoc.id;
            const chunksSnap = await getDocs(collection(node, 'shares', id, 'chunks'));
            const keysSnap = await getDocs(collection(node, 'shares', id, 'keys'));
            chunksSnap.forEach(chk => batch.delete(chk.ref));
            keysSnap.forEach(k => batch.delete(k.ref));
            batch.delete(shareDoc.ref);
          }
          await batch.commit();
        }
      } catch (err: any) {
        console.warn(`Maintenance skipped for node:`, err.message);
      }
    }
  };

  // --- Memoized Values ---
  const activeInboxShares = useMemo(() => {
    return inboxShares.filter(sh => {
      const expiry = sh.expiresAt instanceof Timestamp ? sh.expiresAt.toDate() : new Date(sh.expiresAt);
      return expiry.getTime() > currentTime;
    });
  }, [inboxShares, currentTime]);

  const inboxCount = useMemo(() => {
    return activeInboxShares.filter(sh => {
      if (seenMessageIds.has(sh.id)) return false;
      if (sh.isMessage && showChatPanel && activeChatUID && (sh.ownerId === activeChatUID || sh.recipientIds?.includes(activeChatUID))) {
        return false;
      }
      return true;
    }).length;
  }, [activeInboxShares, seenMessageIds, showChatPanel, activeChatUID]);

  // --- Effects ---

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(Date.now()), 10000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (!user || view === 'setup-profile') return;

    const nodes = [primaryDb, backupDb];
    const unsubs: (() => void)[] = [];

    nodes.forEach((node, idx) => {
      const sharesRef = collection(node, 'shares');
      const q = query(
        sharesRef, 
        where('recipientIds', 'array-contains', user.uid),
        limit(20)
      );

      const unsub = onSnapshot(q, async (snapshot) => {
        // Collect and merge logic...
        const nodeShares = snapshot.docs.map(d => ({ id: d.id, ...d.data(), nodeId: idx } as any));
        
        setInboxShares(prev => {
          const combined = [...prev.filter(p => (p as any).nodeId !== idx), ...nodeShares];
          return combined.sort((a,b) => {
             const tA = a.createdAt?.toMillis ? a.createdAt.toMillis() : new Date(a.createdAt).getTime();
             const tB = b.createdAt?.toMillis ? b.createdAt.toMillis() : new Date(b.createdAt).getTime();
             return tB - tA;
          });
        });
      }, (err) => {
        console.warn(`Inbox node ${idx} restricted:`, err.message);
      });
      unsubs.push(unsub);
    });

    return () => unsubs.forEach(u => u());
  }, [user, view]);

  useEffect(() => {
    if (!user || !showChatPanel) {
      setChatMessages([]);
      return;
    }

    const sharesRef = collection(db, 'shares');
    const combinedQuery = query(
      sharesRef,
      and(
        where('isMessage', '==', true),
        or(
          where('ownerId', '==', user.uid),
          where('recipientIds', 'array-contains', user.uid)
        )
      )
    );

    const unsub = onSnapshot(combinedQuery, async (snap) => {
      const messages: any[] = [];
      const partnersMap = new Map();

      for (const d of snap.docs) {
        const docData = d.data() as ShareData;
        const data = { id: d.id, ...docData };
        
        // Group partners
        const isOwner = data.ownerId === user.uid;
        const pId = isOwner ? data.recipientIds?.[0] : data.ownerId;
        if (!pId) continue;

        // Dynamic Expiry Filter: Vanish immediately if expired
        const expiryDate = data.expiresAt instanceof Timestamp ? data.expiresAt.toDate() : new Date(data.expiresAt);
        if (expiryDate.getTime() < Date.now()) continue;

        if (!partnersMap.has(pId)) {
          partnersMap.set(pId, { uid: pId, lastActivity: data.createdAt?.toMillis() || Date.now() });
        } else {
          const p = partnersMap.get(pId);
          const currentMillis = data.createdAt?.toMillis() || Date.now();
          if (currentMillis > p.lastActivity) p.lastActivity = currentMillis;
        }

        // Collect messages for active chat
        if (pId === activeChatUID) {
          messages.push(data);
        }
      }

      // Sync partners list (resolved usernames)
      // Sync partners list (resolved usernames)
      const partnerList = await Promise.all(
        Array.from(partnersMap.values()).map(async (p: any) => {
          const uSnap = await getDoc(doc(db, 'users', p.uid));
          return { uid: p.uid, username: uSnap.data()?.username || 'Anonymous' };
        })
      );
      setChatPartners(partnerList);

      // Decrypt and sort messages for active chat
      if (activeChatUID) {
        const decrypted = await Promise.all(messages.map(async (m) => {
          if (decryptedCache.current.has(m.id)) return decryptedCache.current.get(m.id);
          try {
            const keySnap = await getDoc(doc(db, 'shares', m.id, 'keys', user.uid));
            if (keySnap.exists()) {
              const key = keySnap.data()?.key;
              const chunksSnap = await getDocs(collection(db, 'shares', m.id, 'chunks'));
              const chunkData = chunksSnap.docs[0].data();
              const encryptedBuffer = base64ToArrayBuffer(chunkData.data);
              const decBuffer = await decryptData(encryptedBuffer, m.iv, key);
              const result = {
                id: m.id,
                text: new TextDecoder().decode(decBuffer),
                senderId: m.ownerId,
                createdAt: m.createdAt?.toMillis() || Date.now()
              };
              decryptedCache.current.set(m.id, result);
              return result;
            }
          } catch (e) { return null; }
          return null;
        }));
        setChatMessages(decrypted.filter(m => m !== null).sort((a,b) => a!.createdAt - b!.createdAt));
      }
    });

    return () => {
      unsub();
      decryptedCache.current.clear();
    };
  }, [user, showChatPanel, activeChatUID, currentTime]);

  const playNotification = () => {
    if (audioRef.current) {
      audioRef.current.currentTime = 0;
      audioRef.current.play().catch((e) => console.log("CipherVault Audio restricted:", e));
    }
  };

  const lastPlayedId = useRef<string | null>(null);

  // Multi-Node Sound Notification
  useEffect(() => {
    if (inboxShares.length > 0) {
      const latest = inboxShares[0];
      if (latest && latest.id !== lastPlayedId.current && prevInboxCount.current > 0) {
        if (latest.ownerId !== user?.uid) {
          playNotification();
          lastPlayedId.current = latest.id;
        }
      }
    }
    prevInboxCount.current = inboxShares.length;
  }, [inboxShares, user]);

  useEffect(() => {
    // Prime audio on first interaction to bypass browser restrictions
    const unlockAudio = () => {
      if (audioRef.current) {
        audioRef.current.play().then(() => {
          audioRef.current?.pause();
          if (audioRef.current) audioRef.current.currentTime = 0;
        }).catch(() => {});
      }
      window.removeEventListener('click', unlockAudio);
    };

    if (!audioRef.current) {
      audioRef.current = new Audio('https://cdn.pixabay.com/audio/2022/03/10/audio_c8c8a73484.mp3');
      audioRef.current.volume = 0.5;
      window.addEventListener('click', unlockAudio);
    }

    return () => window.removeEventListener('click', unlockAudio);
  }, []);

  const profileUnsubRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    const unsub = onAuthStateChanged(primaryAuth, async (u) => {
      setUser(u);
      if (u) {
        // Profile sync from Primary (Identity Node)
        const profileRef = doc(primaryDb, 'users', u.uid);
        onSnapshot(profileRef, (snap) => {
          if (snap.exists()) {
            setProfile(snap.data() as UserProfile);
            setLoading(false);
          } else {
            setView('setup-profile');
            setLoading(false);
          }
        });
      } else {
        setProfile(null);
        setLoading(false);
      }
    });
    return () => unsub();
  }, []);

  useEffect(() => {
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
      window.removeEventListener('hashchange', handleHash);
    };
  }, []);

  // Theme Manager
  useEffect(() => {
    const root = window.document.documentElement;
    localStorage.setItem('vault_theme', theme);
    
    if (theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      root.setAttribute('data-theme', systemTheme);
    } else {
      root.setAttribute('data-theme', theme);
    }

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => {
      if (theme === 'system') {
        root.setAttribute('data-theme', mediaQuery.matches ? 'dark' : 'light');
      }
    };
    
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme]);
  useEffect(() => {
    if (user && isAdmin) {
      pruneExpired();
    }
  }, [user, isAdmin]);

  // Persist seen messages
  useEffect(() => {
    localStorage.setItem('seen_fragments', JSON.stringify(Array.from(seenMessageIds)));
  }, [seenMessageIds]);

  // Mark active chat messages as seen
  useEffect(() => {
    if (activeChatUID && showChatPanel && inboxShares.length > 0) {
      const activePartnerMessages = inboxShares.filter(sh => 
        sh.isMessage && (sh.ownerId === activeChatUID || sh.recipientIds?.includes(activeChatUID))
      );
      
      const newSeen = new Set(seenMessageIds);
      let changed = false;
      activePartnerMessages.forEach(m => {
        if (!newSeen.has(m.id)) {
          newSeen.add(m.id);
          changed = true;
        }
      });
      
      if (changed) {
        setSeenMessageIds(newSeen);
      }
    }
  }, [activeChatUID, showChatPanel, inboxShares, seenMessageIds]);

  const saveProfile = async (username: string) => {
    if (!user) return;
    try {
      const uname = username.toLowerCase().trim();
      const nodes = [primaryDb, backupDb];
      
      for (const node of nodes) {
        try {
          const unameSnap = await getDoc(doc(node, 'usernames', uname));
          if (!unameSnap.exists()) {
            const batch = writeBatch(node);
            batch.set(doc(node, 'users', user.uid), {
              uid: user.uid,
              username: uname,
              displayName: user.displayName || uname,
              email: user.email || '',
              createdAt: serverTimestamp()
            });
            batch.set(doc(node, 'usernames', uname), { uid: user.uid });
            await batch.commit();
          }
        } catch (e) {
          console.warn("Profile sync node failure:", (e as Error).message);
        }
      }
      setView('home');
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleSignIn = async () => {
    try {
      setError(null);
      await signInAll();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const loadShareMetadata = async (id: string) => {
    const path = `shares/${id}`;
    try {
      const docRef = doc(db, 'shares', id);
      const docSnap = await getDoc(docRef);

      let data: ShareData | null = null;

      if (docSnap.exists()) {
        data = docSnap.data() as ShareData;
      } else if (isSupabaseReady() && supabase) {
        // Fallback: Check Supabase
        const { data: sbData } = await supabase
          .from('shares')
          .select('*')
          .eq('id', id)
          .single();
        if (sbData) {
          data = sbData as ShareData;
          setIsBackupActive(true);
        }
      }

      if (data) {
        let senderHandle = null;
        const isDirect = data.recipientIds && data.recipientIds.length > 0;

        if (isDirect && data.ownerId) {
          try {
            const senderSnap = await getDoc(doc(db, 'users', data.ownerId));
            if (senderSnap.exists()) {
              senderHandle = senderSnap.data().username || 'UNKNOWN';
            }
          } catch (e) {
            console.warn("Could not resolve sender handle:", e);
          }
        }
        
        setTargetSenderHandle(senderHandle);
        setTargetShare(data);
        setView('download');
      } else {
        setError('Share not found on any active node. It may have expired.');
      }
    } catch (err) {
      console.error(err);
      if (err instanceof Error && err.message.includes('permissions')) {
        handleFirestoreError(err, OperationType.GET, path);
      }
      setError('Connection to secure node failed.');
    }
  };

  const ensureBackupAuth = async () => {
    if (backupAuth.currentUser) return;
    try {
      const { signInAnonymously } = await import('firebase/auth');
      await signInAnonymously(backupAuth);
    } catch (e) {
      console.warn("Backup Auth Delay:", e);
    }
  };

  const handleFileUpload = async () => {
    if (!file) return;
    
    try {
      setIsEncrypting(true);
      setCurrentPhase("Encrypting data...");
      setError(null);

      const arrayBuffer = await file.arrayBuffer();
      const { encryptedBuffer, iv, key } = await encryptData(arrayBuffer);
      
      setIsEncrypting(false);
      setIsUploading(true);

      const id = generateId();
      const createdAt = new Date();
      const expiresAt = new Date(createdAt.getTime() + expiryMinutes * 60 * 1000);

      const bufferView = new Uint8Array(encryptedBuffer!);
      const chunkSize = 650 * 1024; 
      const chunks: string[] = [];
      for (let i = 0; i < bufferView.length; i += chunkSize) {
        chunks.push(arrayBufferToBase64(bufferView.slice(i, i + chunkSize).buffer));
      }

      const uploadNodes = [
        { auth: primaryAuth, db: primaryDb, name: 'primary' },
        { auth: backupAuth, db: backupDb, name: 'backup' }
      ];

      let uploadSuccess = false;

      for (const node of uploadNodes) {
        try {
          // Ensure backup auth context if we've switched to it
          if (node.name === 'backup') {
            await ensureBackupAuth();
          }

          const shareObj: ShareData = {
            id, iv, chunkCount: chunks.length, fileName: file.name, mimeType: file.type, size: file.size,
            createdAt: serverTimestamp(), expiresAt: Timestamp.fromDate(expiresAt), recipientIds: [], ownerId: node.auth.currentUser?.uid
          };

          await setDoc(doc(node.db, 'shares', id), shareObj);
          for (let i = 0; i < chunks.length; i++) {
            await setDoc(doc(node.db, 'shares', id, 'chunks', `c${i}`), { data: chunks[i], index: i });
          }
          uploadSuccess = true;
          break; 
        } catch (e: any) {
          if (e.message.includes('resource-exhausted') || e.message.includes('permission')) {
             console.warn(`Node ${node.name} restricted, attempting fallback...`);
             continue;
          }
          throw e;
        }
      }

      if (!uploadSuccess) throw new Error("All secure storage nodes are currently at capacity.");

      const link = `${window.location.origin}/#share=${id}&key=${encodeURIComponent(key)}`;
      setGeneratedLink(link);
      setShareId(id);
      setSecretKey(key);
      setView('success');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsEncrypting(false);
      setIsUploading(false);
    }
  };

  const processSecureFile = async (): Promise<{ url: string; name: string; type: string } | null> => {
    if (!targetShare || !secretKey) return null;

    try {
      setIsDecrypting(true);
      const nodes = [primaryDb, backupDb];
      let metadata: any = null;
      let chunksData: ChunkData[] = [];
      let foundOnNode = false;

      for (const node of nodes) {
        try {
          const snap = await getDoc(doc(node, 'shares', targetShare.id));
          if (snap.exists()) {
            metadata = snap.data();
            const cSnap = await getDocs(collection(node, 'shares', targetShare.id, 'chunks'));
            // Support both 'index' and 'chunk_index' field names
            chunksData = cSnap.docs.map(d => {
              const dData = d.data();
              return { data: dData.data, index: dData.index ?? dData.chunk_index } as ChunkData;
            }).sort((a,b) => a.index - b.index);
            foundOnNode = true;
            break;
          }
        } catch (e) {
          console.warn("Node fetch failed, trying next...");
        }
      }

      // Check Supabase if not found on Firebase nodes
      if (!foundOnNode && isSupabaseReady() && supabase) {
        const { data: sbChunks } = await supabase
          .from('chunks')
          .select('*')
          .eq('share_id', targetShare.id)
          .order('chunk_index', { ascending: true });
        
        if (sbChunks && sbChunks.length > 0) {
          chunksData = sbChunks.map(c => ({ data: c.data, index: c.chunk_index }));
          metadata = targetShare;
          foundOnNode = true;
          setIsBackupActive(true);
        }
      }

      if (!foundOnNode || !metadata || chunksData.length === 0) {
        throw new Error("File chunks not found on any network node.");
      }

      const combinedSize = chunksData.reduce((acc, c) => acc + base64ToArrayBuffer(c.data).byteLength, 0);
      const combined = new Uint8Array(combinedSize);
      let offset = 0;
      chunksData.forEach(c => {
        const buf = new Uint8Array(base64ToArrayBuffer(c.data));
        combined.set(buf, offset);
        offset += buf.byteLength;
      });

      const decryptedBuffer = await decryptData(combined.buffer, targetShare.iv, secretKey);
      const blob = new Blob([decryptedBuffer], { type: targetShare.mimeType });
      return { url: URL.createObjectURL(blob), name: targetShare.fileName, type: targetShare.mimeType };
    } catch (err: any) {
      console.error("Encryption/Decryption spectrum failure:", err);
      setError(err.message || "Decryption failed.");
      return null;
    } finally {
      setIsDecrypting(false);
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
      setDecryptedFile(file);
      setShowPreview(true);
    }
  };

  const directShareWithUser = async (targetUsername: string) => {
    if (!profile || !shareId || !secretKey) return;
    try {
      setError(null);
      const uname = targetUsername.toLowerCase().trim();
      let recipientUid = null;

      // 1. Try Primary
      try {
        const uSnap = await getDoc(doc(primaryDb, 'usernames', uname));
        if (uSnap.exists()) recipientUid = uSnap.data().uid;
      } catch (e) { console.warn("Primary handle resolution delay"); }

      // 2. Try Backup
      if (!recipientUid) {
        try {
          const uSnap = await getDoc(doc(backupDb, 'usernames', uname));
          if (uSnap.exists()) recipientUid = uSnap.data().uid;
        } catch (e) { console.warn("Backup handle resolution delay"); }
      }

      // 3. Try Supabase
      if (!recipientUid && isSupabaseReady() && supabase) {
        const { data: sbUname } = await supabase.from('usernames').select('uid').eq('username', uname).single();
        if (sbUname) recipientUid = sbUname.uid;
      }

      if (!recipientUid) throw new Error("Recipient handle not found in the cluster spectrum.");
      if (recipientUid === user?.uid) throw new Error("You cannot share with yourself.");

      const uploadNodes = [
        { auth: primaryAuth, db: primaryDb, name: 'primary' },
        { auth: backupAuth, db: backupDb, name: 'backup' }
      ];

      let shareSuccess = false;
      for (const node of uploadNodes) {
        try {
          const shareRef = doc(node.db, 'shares', shareId);
          const batch = writeBatch(node.db);
          batch.set(doc(shareRef, 'keys', recipientUid), { key: secretKey });
          batch.update(shareRef, { recipientIds: arrayUnion(recipientUid) });
          await batch.commit();
          shareSuccess = true;
          break;
        } catch (e) { continue; }
      }
      
      if (!shareSuccess) throw new Error("Synchronization Error: Multi-node identity relay failed.");
      return true;
    } catch (err: any) {
      if (err.code === 'resource-exhausted' || err.message?.includes('resource-exhausted')) {
        setQuotaExceeded(true);
        setError("System Quota Reached: Daily share limit exceeded.");
      } else {
        setError(err.message);
      }
      return false;
    }
  };

  const sendSecureMessage = async () => {
    if (!profile || !messageRecipient || !messageText) return;
    
    try {
      setIsSendingMessage(true);
      setError(null);

      const targetUname = messageRecipient.toLowerCase().trim();
      let recipientUid = null;

      // 1. Try Primary
      try {
        const uSnap = await getDoc(doc(primaryDb, 'usernames', targetUname));
        if (uSnap.exists()) recipientUid = uSnap.data().uid;
      } catch (e) { console.warn("Primary resolution pending..."); }

      // 2. Try Backup
      if (!recipientUid) {
        try {
          const uSnap = await getDoc(doc(backupDb, 'usernames', targetUname));
          if (uSnap.exists()) recipientUid = uSnap.data().uid;
        } catch (e) { console.warn("Backup resolution pending..."); }
      }

      // 3. Try Supabase
      if (!recipientUid && isSupabaseReady() && supabase) {
        const { data: sbUname } = await supabase.from('usernames').select('uid').eq('username', targetUname).single();
        if (sbUname) recipientUid = sbUname.uid;
      }

      if (!recipientUid) throw new Error("Recipient handle not detected in current cluster.");
      
      await sendChatMessage(recipientUid, messageText);

      setMessageText('');
      setMessageRecipient('');
      setError(`[SECURE TRANSMISSION COMPLETE] Message relayed to @${targetUname}`);
      setTimeout(() => setError(null), 5000);
    } catch (err: any) {
      console.error(err);
      if (err.code === 'resource-exhausted' || err.message?.includes('resource-exhausted')) {
        setQuotaExceeded(true);
        setError("Transmission Failure: Daily system quota reached. Please try again tomorrow.");
      } else {
        setError(err.message || "Encryption relay failure.");
      }
    } finally {
      setIsSendingMessage(false);
    }
  };

  const sendChatMessage = async (recipientUid: string, text: string) => {
    if (!user || !text || !recipientUid) return;

    try {
      const { encryptedBuffer, iv, key } = await encryptData(text);
      const id = generateId();
      const encryptedBase64 = arrayBufferToBase64(encryptedBuffer!);

      const expireAt = new Date();
      expireAt.setMinutes(expireAt.getMinutes() + expiryMinutes);

      const shareObj: ShareData = {
        id,
        iv,
        chunkCount: 1,
        fileName: "Secure Message",
        mimeType: "text/plain",
        size: text.length,
        createdAt: serverTimestamp(),
        expiresAt: Timestamp.fromDate(expireAt),
        recipientIds: [recipientUid],
        ownerId: user.uid,
        isMessage: true
      };

      // Primary: Firebase
      try {
        const batch = writeBatch(db);
        batch.set(doc(db, 'shares', id), shareObj);
        batch.set(doc(db, 'shares', id, 'chunks', 'm0'), { data: encryptedBase64, index: 0 });
        batch.set(doc(db, 'shares', id, 'keys', recipientUid), { key });
        batch.set(doc(db, 'shares', id, 'keys', user.uid), { key });
        await batch.commit();
      } catch (fbErr: any) {
        const isQuota = fbErr.code === 'resource-exhausted' || fbErr.message?.includes('resource-exhausted');
        if (isQuota && isSupabaseReady() && supabase) {
          setIsBackupActive(true);
          setQuotaExceeded(true);
          
          await supabase.from('shares').insert({
            id,
            iv,
            chunk_count: 1,
            file_name: "Secure Message",
            mime_type: "text/plain",
            size: text.length,
            owner_id: user.uid,
            recipient_ids: [recipientUid],
            expires_at: expireAt.toISOString(),
            is_message: true
          });

          await supabase.from('chunks').insert({ share_id: id, data: encryptedBase64, chunk_index: 0 });
          await supabase.from('keys').insert([
            { share_id: id, user_id: recipientUid, key },
            { share_id: id, user_id: user.uid, key }
          ]);
        } else {
          throw fbErr;
        }
      }
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
      
      // Mark as seen immediately on click
      if (!seenMessageIds.has(share.id)) {
        const next = new Set(seenMessageIds);
        next.add(share.id);
        setSeenMessageIds(next);
      }

      let key = null;

      // Try Firebase
      try {
        const keySnap = await getDoc(doc(db, 'shares', share.id, 'keys', user!.uid));
        if (keySnap.exists()) {
           key = keySnap.data()?.key;
        }
      } catch (fbErr) {
        console.warn("Firebase key fetch failed, trying backup...");
      }

      // Try Supabase fallback
      if (!key && isSupabaseReady() && supabase) {
        const { data, error } = await supabase
          .from('keys')
          .select('key')
          .eq('share_id', share.id)
          .eq('user_id', user!.uid)
          .single();
        
        if (data) {
          key = data.key;
          setIsBackupActive(true);
        }
      }

      if (!key) throw new Error("Decryption key was not found on any node.");
      
      setSecretKey(key);
      setShareId(share.id);
      
      let senderHandle = null;
      const isDirect = share.recipientIds && share.recipientIds.length > 0;

      if (isDirect && share.ownerId) {
        const senderSnap = await getDoc(doc(db, 'users', share.ownerId));
        if (senderSnap.exists()) {
          senderHandle = senderSnap.data().username || 'UNKNOWN';
        }
      }
      setTargetSenderHandle(senderHandle);
      setTargetShare(share);

      if (share.isMessage) {
        // Auto-decrypt message using existing helpers
        setIsDecrypting(true);
        const chunksSnap = await getDocs(collection(db, 'shares', share.id, 'chunks'));
        const chunkData = chunksSnap.docs[0].data();
        
        const encryptedBuffer = base64ToArrayBuffer(chunkData.data);
        const decryptedBuffer = await decryptData(encryptedBuffer, share.iv, key);
        
        const dec = new TextDecoder();
        
        setDecryptedMessage({ 
          text: dec.decode(decryptedBuffer),
          sender: senderHandle || ''
        });
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
    setGeneratedLink('');
    setDecryptedFile(null);
    setError(null);
    setView('home');
  };

  const createPersonalKey = async (providedKey: string) => {
    if (!profile || !user || !providedKey) return;
    const currentKeys = profile.privateKeys || [];
    if (currentKeys.length >= 5) {
      setError("Vault Protocol Limit: Maximum of 5 private keys reached.");
      return;
    }

    const newKey = providedKey.trim();
    if (newKey.length < 12 || newKey.length > 20) {
      setError("Invalid Key Length: Custom keys must be between 12-20 characters.");
      return;
    }

    if (currentKeys.includes(newKey)) {
      setError("Key Collision: This key is already registered in your terminal profile.");
      return;
    }

    try {
      await setDoc(doc(db, 'users', user.uid), {
        privateKeys: arrayUnion(newKey)
      }, { merge: true });
      
      setCustomKeyInput('');
      setError(`[KEY_SYNC_SUCCESS] Custom key registered: ${newKey}`);
      setTimeout(() => setError(null), 5000);
    } catch (err) {
      console.error(err);
      setError("Network Error: Failed to synchronize new key to core.");
    }
  };

  const deletePersonalKey = async (keyToRemove: string) => {
    if (!user || !profile) return;
    try {
      await updateDoc(doc(db, 'users', user.uid), {
        privateKeys: arrayRemove(keyToRemove)
      });
      setError(`[KEY_DELETED] Secure key removed from terminal.`);
      setTimeout(() => setError(null), 3000);
    } catch (err) {
      console.error(err);
      setError("Failed to delete key.");
    }
  };

  const editPersonalKey = async (oldKey: string, newValue: string) => {
    if (!user || !profile || !newValue) return;
    const sanitizedKey = newValue.trim();
    if (sanitizedKey.length < 12 || sanitizedKey.length > 20) {
      setError("Invalid Key Length: Custom keys must be between 12-20 characters.");
      return;
    }
    try {
      const currentKeys = [...(profile.privateKeys || [])];
      const index = currentKeys.indexOf(oldKey);
      if (index !== -1) {
        currentKeys[index] = sanitizedKey;
        await updateDoc(doc(db, 'users', user.uid), {
          privateKeys: currentKeys
        });
        setEditingKeyIndex(null);
        setError(`[KEY_EDIT_SUCCESS] Key updated successfully.`);
        setTimeout(() => setError(null), 3000);
      }
    } catch (err) {
      console.error(err);
      setError("Failed to update key.");
    }
  };

  const bindShareToKey = async (customKey: string) => {
    if (!shareId || !secretKey) return;
    try {
      setIsResolvingKey(true);
      const mappingRef = doc(db, 'custom_keys', customKey);
      
      // Check if key is already in use for another active share
      const existing = await getDoc(mappingRef);
      if (existing.exists()) {
        const data = existing.data();
        if (data.expiresAt.toMillis() > Date.now()) {
          throw new Error("Target key is currently bonded to another active transmission.");
        }
      }

      const expiresAtDate = targetShare?.expiresAt instanceof Timestamp ? targetShare.expiresAt.toDate() : 
                        (targetShare?.expiresAt ? new Date(targetShare.expiresAt) : new Date(Date.now() + 30 * 60 * 1000));
      const expiresAt = Timestamp.fromDate(expiresAtDate);

      // Primary: Firebase
      try {
        await setDoc(mappingRef, {
          shareId,
          secretKey,
          expiresAt
        });
      } catch (fbErr: any) {
         console.warn("Firebase key sync failed, continuing with backup map...");
      }

      // Secondary: Supabase (Mandatory Sync if available)
      if (isSupabaseReady() && supabase) {
        await supabase.from('custom_keys').upsert({
          key_id: customKey,
          share_id: shareId,
          secret_key: secretKey,
          expires_at: expiresAtDate.toISOString()
        });
      }
      
      setError(`[BOND_SUCCESS] Share mapped to private key: ${customKey}`);
      setTimeout(() => setError(null), 5000);
    } catch (err: any) {
      setError(err.message || "Failed to bind private key.");
    } finally {
      setIsResolvingKey(false);
    }
  };

  const handleKeyReceive = async () => {
    if (!entryKey) return;
    try {
      setIsResolvingKey(true);
      setError(null);
      
      let keyData = null;

      // 1. Try Firebase
      try {
        const mappingSnap = await getDoc(doc(db, 'custom_keys', entryKey));
        if (mappingSnap.exists()) {
          const data = mappingSnap.data();
          if (data.expiresAt.toMillis() >= Date.now()) {
            keyData = data;
          }
        }
      } catch (e) {
        console.warn("Primary key resolution failed...");
      }

      // 2. Try Supabase Fallback
      if (!keyData && isSupabaseReady() && supabase) {
        const { data: sbKey } = await supabase
          .from('custom_keys')
          .select('*')
          .eq('key_id', entryKey)
          .single();
        
        if (sbKey && new Date(sbKey.expires_at).getTime() >= Date.now()) {
          keyData = { 
            shareId: sbKey.share_id, 
            secretKey: sbKey.secret_key 
          };
          setIsBackupActive(true);
        }
      }

      if (!keyData) {
        throw new Error("Key not found in active spectrum or has expired.");
      }

      setShareId(keyData.shareId);
      setSecretKey(keyData.secretKey);
      setEntryKey('');
      setShowPrivateKeyPanel(false);
      await loadShareMetadata(keyData.shareId);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsResolvingKey(false);
    }
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
      <div className="min-h-screen flex items-center justify-center bg-bg-base">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <>
      {/* Private Key Panel Trigger (Left Arrow) */}
      <motion.button
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        onClick={() => setShowPrivateKeyPanel(true)}
        className="fixed left-0 top-[22%] -translate-y-1/2 z-[100] h-16 md:h-32 w-5 md:w-8 bg-bg-card border-r border-y border-border-main rounded-r-xl flex items-center justify-center hover:bg-bg-base/40 transition-all group shadow-2xl"
      >
        <div className="absolute inset-0 bg-blue-500/5 group-hover:bg-blue-500/10 transition-colors rounded-r-xl" />
        <ChevronRight className="w-3 h-3 md:w-4 md:h-4 text-blue-500 group-hover:scale-110 transition-transform" />
        <div className="absolute -right-6 md:-right-10 top-1/2 -translate-y-1/2 rotate-90 whitespace-nowrap text-[5px] md:text-[8px] font-mono font-black text-blue-500/40 uppercase tracking-[0.2em] md:tracking-[0.3em] pointer-events-none">
          SECURE_ID
        </div>
      </motion.button>

      {/* Private Key Receive Panel */}
      <AnimatePresence>
        {showPrivateKeyPanel && (
          <motion.div
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed inset-y-0 left-0 w-80 bg-bg-card border-r border-border-main z-[150] shadow-2xl overflow-hidden flex flex-col"
          >
            <div className="scanning scanline opacity-10" />
            <div className="p-6 border-b border-border-main bg-bg-base/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-blue-500 glow-blue transition-all group-hover:scale-110" />
                <span className="text-xs font-mono font-black text-text-main uppercase tracking-widest">Quantum Extraction</span>
              </div>
              <button 
                onClick={() => setShowPrivateKeyPanel(false)}
                className="p-2 hover:bg-black/5 rounded-lg text-text-sub transition-all"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            </div>

            <div className="flex-1 p-6 space-y-8 overflow-y-auto">
              <div className="space-y-4">
                <div className="p-4 bg-blue-500/5 rounded-xl border border-blue-500/10">
                  <p className="text-[10px] font-mono text-text-sub leading-relaxed uppercase">
                    Enter your 15-character secure private key to recover the bonded transmission directly from the network.
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="text-[9px] font-mono font-black text-blue-500 uppercase tracking-widest ml-1">Secure Identifier</label>
                  <div className="relative">
                    <Hash className="absolute left-3 top-1/2 -translate-y-1/2 w-3 h-3 text-blue-500/50" />
                    <input 
                      value={entryKey}
                      onChange={(e) => setEntryKey(e.target.value)}
                      placeholder="e.g. A#3f-L9!xZ2*q7"
                      className="w-full bg-bg-base border border-border-main rounded-xl py-3 pl-9 pr-4 text-xs font-mono text-text-main placeholder:text-text-sub outline-none focus:border-blue-500/30 transition-all font-bold"
                    />
                  </div>
                </div>

                {error && (
                  <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2">
                    <AlertCircle className="w-3 h-3 text-red-500" />
                    <span className="text-[9px] font-mono text-red-400 uppercase font-bold leading-tight">{error}</span>
                  </div>
                )}

                <button 
                  onClick={handleKeyReceive}
                  disabled={!entryKey || isResolvingKey}
                  className="w-full py-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-xl font-mono font-bold text-xs uppercase tracking-widest transition-all shadow-[0_4px_20px_rgba(37,99,235,0.2)] flex items-center justify-center gap-2"
                >
                  {isResolvingKey ? <Loader2 className="w-4 h-4 animate-spin text-white/50" /> : <Fingerprint className="w-4 h-4 text-white/50" />}
                  {isResolvingKey ? 'Resolving Spectrum...' : 'Execute Recovery'}
                </button>
              </div>

              <div className="pt-8 border-t border-border-main">
                <div className="flex items-center gap-2 mb-4">
                  <Info className="w-3 h-3 text-slate-500" />
                  <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest">Protocol Rules</span>
                </div>
                <ul className="space-y-3">
                  <li className="flex gap-2 items-start">
                    <div className="w-1 h-1 rounded-full bg-blue-500 mt-1" />
                    <p className="text-[9px] font-mono text-slate-500 uppercase leading-relaxed">Keys are one-time use identifiers bonded to specific secure fragments.</p>
                  </li>
                  <li className="flex gap-2 items-start">
                    <div className="w-1 h-1 rounded-full bg-blue-500 mt-1" />
                    <p className="text-[9px] font-mono text-slate-500 uppercase leading-relaxed">Expired shares result in immediate key dissociation from the vault.</p>
                  </li>
                </ul>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="min-h-screen bg-bg-base px-2 py-4 md:p-8 selection:bg-blue-500/30 transition-colors overflow-x-hidden">
      {/* GLOBAL_SYSTEM_MONITORING: QUOTA_LOCK_DETECTION */}
      <AnimatePresence>
        {quotaExceeded && (
          <motion.div 
            initial={{ y: -100, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -100, opacity: 0 }}
            className="fixed top-0 left-0 right-0 z-[200] bg-bg-base/95 border-b border-red-500 shadow-[0_0_50px_rgba(239,68,68,0.2)]"
          >
            <div className="scanning scanline !bg-red-500/50 opacity-20" />
            <div className="max-w-4xl mx-auto px-4 md:px-6 py-3 md:py-4 flex flex-col md:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-4 text-center md:text-left">
                <div className="relative shrink-0">
                   <div className="absolute inset-0 bg-red-500/20 blur-xl animate-pulse" />
                   <ShieldAlert className="w-6 h-6 md:w-8 md:h-8 text-red-500 glow-red animate-pulse" />
                </div>
                <div>
                   <h3 className="text-[10px] md:text-xs font-mono font-black text-red-500 uppercase tracking-[0.2em] md:tracking-[0.3em]">
                     {isBackupActive ? 'FAILOVER_ACTIVE: BACKUP_NODE_READY' : 'Critical_System_Lock: Quota_Exhausted'}
                   </h3>
                   <p className="text-[8px] md:text-[9px] font-mono text-slate-500 uppercase tracking-[0.1em] mt-0.5 md:mt-1">
                     {isBackupActive 
                       ? 'Primary Node Offline. Secure traffic routed to Supabase redundancy.'
                       : 'Primary Node (Firebase) offline. All secure writes are locked.'}
                   </p>
                </div>
              </div>
              <button 
                onClick={() => setQuotaExceeded(false)}
                className="w-full md:w-auto px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/30 rounded-lg text-[8px] md:text-[9px] font-mono font-black uppercase tracking-widest transition-all"
              >
                Acknowledge_Relay
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Header */}
      <nav className="max-w-4xl mx-auto flex justify-between items-center mb-8 md:mb-12 px-2 md:px-0 gap-2">
        <div className="flex items-center gap-1.5 md:gap-4 cursor-pointer shrink-0" onClick={reset}>
          <div className="flex items-center pr-2 md:pr-4 border-r border-white/5">
            <Shield className="w-5 h-5 md:w-8 md:h-8 text-blue-500 glow-blue animate-pulse-glow" />
          </div>
          <div>
            <div className="flex items-center gap-2 md:gap-3">
              <h1 className="font-mono font-black tracking-tight md:tracking-[0.2em] text-sm md:text-xl text-text-main whitespace-nowrap">
                <span className="hidden sm:inline">CIPHER</span><span className="text-blue-500">VAULT</span>
              </h1>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 md:gap-4 overflow-hidden">
          {/* Theme Switcher */}
          <div className="flex items-center bg-bg-card/40 p-0.5 md:p-1 rounded-lg border border-border-main shrink-0">
            <button 
              onClick={() => setTheme('light')}
              className={`p-1 md:p-1.5 rounded-md transition-all ${theme === 'light' ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/20' : 'text-slate-500 hover:text-white'}`}
            >
              <Sun className="w-3 h-3 md:w-4 md:h-4" />
            </button>
            <button 
              onClick={() => setTheme('dark')}
              className={`p-1 md:p-1.5 rounded-md transition-all ${theme === 'dark' ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/20' : 'text-slate-500 hover:text-white'}`}
            >
              <Moon className="w-3 h-3 md:w-4 md:h-4" />
            </button>
            <button 
              onClick={() => setTheme('system')}
              className={`p-1 md:p-1.5 rounded-md transition-all ${theme === 'system' ? 'bg-blue-500 text-white shadow-lg shadow-blue-500/20' : 'text-slate-500 hover:text-white'}`}
            >
              <Monitor className="w-3 h-3 md:w-4 md:h-4" />
            </button>
          </div>

          {user && profile && (
            <button 
              onClick={() => setShowInbox(!showInbox)}
              className="relative p-1.5 md:p-2 bg-white/5 hover:bg-white/10 rounded-lg technical-border transition-all shrink-0"
            >
              <Bell className={`w-3.5 h-3.5 md:w-5 md:h-5 ${inboxCount > 0 ? 'text-blue-500 animate-pulse' : 'text-slate-500'}`} />
              {inboxCount > 0 && (
                <span className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-blue-600 text-[8px] md:text-[10px] font-bold rounded-full flex items-center justify-center text-white border-2 border-bg-base">
                  {inboxCount}
                </span>
              )}
            </button>
          )}

          {user ? (
            <div className="flex items-center gap-2 md:gap-3 shrink-0">
              <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                <UserIcon className="w-3 h-3 text-blue-500 glow-blue" />
                <span className="text-xs font-mono font-bold text-blue-400 uppercase tracking-tighter">
                  {profile?.username ? `@${profile.username}` : (user.email || 'Secure User')}
                </span>
              </div>
              <button 
                onClick={signOutAll}
                className="p-1.5 md:p-0 text-text-sub hover:text-text-main transition-colors flex items-center gap-1.5"
                title="Disconnect from Terminal"
              >
                <LogOut className="w-4 h-4 md:hidden" />
                <span className="hidden md:inline text-xs font-mono uppercase tracking-wider">Disconnect</span>
              </button>
              {isAdmin && (
                <button 
                  onClick={() => setShowAdmin(!showAdmin)}
                  className={`flex items-center gap-1.5 transition-all shrink-0 ${showAdmin ? 'text-red-500 animate-pulse' : 'text-slate-500 hover:text-white'}`}
                  title="System Control Node"
                >
                  <Terminal className={`w-4 h-4 p-1 rounded ${showAdmin ? 'bg-red-500/10 border border-red-500/50' : 'bg-white/5 border border-white/10'}`} />
                  <span className="hidden md:inline text-[10px] font-mono font-black uppercase tracking-widest">SYS_CTRL</span>
                </button>
              )}
            </div>
          ) : (
            <button 
              onClick={handleSignIn}
              className="text-[10px] md:text-xs font-mono uppercase tracking-wider bg-blue-600 hover:bg-blue-500 active:scale-95 px-3 md:px-4 py-1.5 md:py-2 rounded-md border border-blue-500/50 transition-all text-white whitespace-nowrap shrink-0 shadow-[0_0_15px_rgba(59,130,246,0.2)] active:shadow-[0_0_25px_rgba(59,130,246,0.6)]"
            >
              Sign In
            </button>
          )}
        </div>
      </nav>

      <main className="max-w-md mx-auto relative cursor-default sm:px-0">
        <AnimatePresence mode="wait">
          
          {/* Inbox Overlay */}
          <AnimatePresence>
            {showInbox && (
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className="fixed top-20 right-4 left-4 sm:left-auto sm:w-80 max-h-[70vh] bg-bg-card border border-border-main rounded-2xl shadow-2xl z-40 overflow-hidden flex flex-col"
              >
                  <div className="p-4 border-b border-border-main flex items-center justify-between bg-bg-base/40">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-blue-500 animate-pulse glow-blue" />
                      <span className="text-[10px] font-mono font-black uppercase tracking-[0.2em] text-text-main">SECURE_INBOX_v2.1</span>
                    </div>
                    <button onClick={() => setShowInbox(false)} className="w-8 h-8 flex items-center justify-center bg-bg-base/5 hover:bg-bg-base/10 rounded-lg text-text-sub hover:text-text-main transition-all">
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                
                <div className="flex-1 overflow-y-auto p-2 space-y-2">
                  {activeInboxShares.length === 0 ? (
                    <div className="py-12 text-center">
                      <Shield className="w-8 h-8 text-text-sub/30 mx-auto mb-3" />
                      <p className="text-[10px] font-mono text-text-sub uppercase tracking-widest">No direct fragments found.</p>
                    </div>
                  ) : (
                    activeInboxShares.map(share => (
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
                            <p className={`text-[10px] font-bold truncate group-hover:text-blue-400 transition-colors uppercase ${share.isMessage ? 'text-purple-400' : 'text-text-main'}`}>
                              {share.isMessage ? 'Secure Message' : share.fileName}
                            </p>
                            <p className="text-[8px] font-mono text-slate-500 mt-1 uppercase">
                              {share.isMessage ? 'Encrypted Text' : formatSize(share.size)} • <Countdown expiresAt={share.expiresAt} />
                            </p>
                            {share.senderHandle && (
                              <div className="mt-1 flex items-center gap-1">
                                <span className="text-[7px] text-blue-500/60 font-black uppercase">From:</span>
                                <span className="text-[7px] text-blue-400 font-bold">@{share.senderHandle}</span>
                              </div>
                            )}
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
                
                <div className="p-3 bg-bg-base/40 border-t border-border-main">
                  <p className="text-[8px] font-mono text-text-sub text-center uppercase tracking-tighter">
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
              className="bg-bg-card p-8 rounded-2xl technical-border flex flex-col items-center text-center shadow-2xl"
            >
              <div className="p-4 bg-blue-500/10 rounded-2xl mb-6 relative">
                <UserIcon className="w-8 h-8 text-blue-500" />
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-blue-600 rounded-full animate-ping" />
              </div>
              
              <h2 className="text-xl font-mono font-bold text-text-main mb-2 uppercase tracking-tighter">Initialize Identity</h2>
              <p className="text-xs text-text-sub mb-8 font-mono leading-relaxed lowercase italic line-clamp-2">
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
                    className="w-full bg-bg-base/40 border border-border-main focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 rounded-xl py-3 pl-10 pr-4 text-sm font-mono text-text-main placeholder:text-text-sub outline-none transition-all"
                  />
                </div>
                
                {error && (
                  <p className="text-[10px] text-red-400 font-mono uppercase tracking-tighter bg-red-500/10 p-2 rounded-lg border border-red-500/20">
                    {error}
                  </p>
                )}

                <button 
                  type="submit"
                  disabled={quotaExceeded}
                  className="w-full py-3 btn-primary font-mono text-xs font-bold uppercase tracking-widest active-glow"
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
              <div className="bg-bg-card p-3 sm:p-8 rounded-xl technical-border text-center">
                <div className="flex justify-center mb-6">
                  <div className="p-4 bg-blue-500/10 rounded-full border border-blue-500/20 shadow-[0_0_30px_rgba(59,130,246,0.1)]">
                    <Shield className="w-12 h-12 text-blue-500 animate-pulse-glow" />
                  </div>
                </div>
                <div className="relative mb-12 text-left">
                  <div className="absolute top-0 left-0 w-8 h-[1px] bg-blue-500/50" />
                  <div className="absolute top-0 left-0 w-[1px] h-8 bg-blue-500/50" />
                  <div className="pt-6 pl-2 sm:pl-6">
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-[10px] font-black text-blue-500/50 font-mono">01 //</span>
                      <h2 className="text-2xl sm:text-3xl font-mono font-black text-text-main uppercase tracking-tighter">Access Terminal</h2>
                    </div>
                    <p className="text-[10px] text-text-sub uppercase tracking-[0.3em] font-bold">Select required operational mode</p>
                  </div>
                </div>

                <div className="grid gap-4">
                    <button 
                      onClick={() => setView('upload')}
                      className="group relative bg-bg-card hover:bg-bg-base px-3 py-5 sm:p-8 rounded-2xl transition-all text-left flex items-center justify-between border border-border-main hover:border-blue-500/30 shadow-2xl active:scale-[0.98] active-glow overflow-hidden"
                    >
                      <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-blue-500/10 to-transparent" />
                      <div className="relative z-10">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-[8px] font-black text-blue-500 font-mono">OP_TYPE: DEPOSIT</span>
                          <div className="w-1 h-1 rounded-full bg-blue-500 glow-blue animate-pulse" />
                        </div>
                        <h3 className="font-mono font-black text-lg sm:text-xl leading-none text-text-main tracking-widest uppercase mb-1">Deposit Data</h3>
                        <p className="text-[9px] uppercase font-mono tracking-[0.2em] text-text-sub">Encrypt & Store Secure Fragments</p>
                      </div>
                      <div className="relative">
                        <div className="absolute inset-0 bg-blue-500/10 blur-xl group-hover:opacity-100 opacity-0 transition-opacity" />
                        <Lock className="w-8 h-8 relative z-10 text-blue-500/40 group-hover:text-blue-500 group-hover:scale-110 transition-all pointer-events-none" />
                      </div>
                    </button>

                  <div className="relative">
                    <div className="absolute inset-0 flex items-center" aria-hidden="true">
                      <div className="w-full border-t border-border-main"></div>
                    </div>
                    <div className="relative flex justify-center">
                      <span className="bg-bg-card px-4 text-[10px] font-mono text-text-sub uppercase tracking-widest">or receive</span>
                    </div>
                  </div>

                  <div className="bg-bg-base/5 p-3 sm:p-6 rounded-xl border border-border-main text-left">
                    <h3 className="font-mono font-bold text-base sm:text-lg leading-none mb-4 uppercase text-text-main">Direct Extraction</h3>
                    <div className="flex gap-2">
                      <input 
                        type="text"
                        placeholder="Paste secure link here..."
                        value={manualLink}
                        onChange={(e) => setManualLink(e.target.value)}
                        className="flex-1 bg-bg-base/40 border border-border-main rounded-lg px-4 py-3 text-xs font-mono text-blue-400 placeholder:text-text-sub focus:outline-none focus:border-blue-500/50"
                      />
                        <button 
                          onClick={handleManualReceive}
                          disabled={!manualLink}
                          className="bg-bg-base/10 hover:bg-bg-base/20 p-3 rounded-lg transition-colors group-hover:bg-blue-500/10 disabled:opacity-30"
                        >
                          <Unlock className="w-5 h-5 group-hover:glow-blue transition-all" />
                        </button>
                    </div>
                  </div>

                    <div className="bg-blue-500/5 p-3 sm:p-6 rounded-xl border border-blue-500/10 text-left">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                        <h3 className="font-mono font-bold text-base sm:text-lg leading-none uppercase flex items-center gap-2">
                           <Mail className="w-4 h-4 text-blue-400" />
                           Quantum Message
                        </h3>
                        <button 
                          onClick={() => setShowChatPanel(true)}
                          className="px-3 py-2 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/20 rounded-lg text-[9px] font-mono font-bold uppercase tracking-widest transition-all flex items-center justify-center gap-2"
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
                          className="w-full bg-bg-base/40 border border-border-main focus:border-blue-500/30 rounded-lg py-2 pl-9 pr-3 text-[10px] font-mono text-text-main placeholder:text-text-sub outline-none transition-all"
                        />
                      </div>
                      <textarea 
                        placeholder="Type secure message (Encrypted locally)..."
                        value={messageText}
                        onChange={(e) => setMessageText(e.target.value)}
                        rows={3}
                        className="w-full bg-bg-base/40 border border-border-main focus:border-blue-500/30 rounded-lg p-3 text-[10px] font-mono text-text-main placeholder:text-text-sub outline-none transition-all resize-none"
                      />
                      <button 
                        disabled={isSendingMessage || !messageRecipient || !messageText || quotaExceeded}
                        onClick={sendSecureMessage}
                        className="w-full btn-primary py-4 rounded-xl text-[11px] font-mono font-black uppercase tracking-[0.2em] flex items-center justify-center gap-3 shadow-[0_0_20px_rgba(59,130,246,0.1)] active-glow"
                      >
                        {isSendingMessage ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          <Send className="w-4 h-4" />
                        )}
                        Relay Secure Message
                      </button>
                    </div>
                  </div>
                </div>

                {isAdmin && showAdmin && (
                  <AdminDashboard 
                onPrune={pruneExpired} 
                quotaExceeded={quotaExceeded}
              />
                )}
              </div>

              <div className="grid grid-cols-3 gap-2">
                {[
                  { label: "AES-256-GCM", icon: Shield },
                  { label: "ZERO-K_RELAY", icon: Lock },
                  { label: "RESILIENCY_UP", icon: Zap }
                ].map((item, idx) => (
                  <div key={idx} className="bg-bg-base/40 border border-border-main p-4 rounded-xl flex flex-col items-center gap-2 technical-border group hover:border-blue-500/30 transition-all">
                    <item.icon className="w-4 h-4 text-text-sub group-hover:text-blue-500 group-hover:glow-blue transition-all" />
                    <span className="text-[7px] font-mono font-black uppercase tracking-[0.3em] text-text-sub group-hover:text-blue-400 transition-colors">{item.label}</span>
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
              className="bg-bg-card p-6 rounded-xl technical-border overflow-hidden"
            >
              <div className="scanning scanline" />
              <h2 className="text-lg font-mono font-bold flex items-center gap-2 mb-4 text-text-main">
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
                    <p className="mt-3 text-sm font-medium text-text-main max-w-[200px] truncate">{file.name}</p>
                    <p className="text-[10px] font-mono text-text-sub mt-1">{formatSize(file.size)}</p>
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
                        {[5, 15, 60, 1440].map(m => (
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
                    disabled={isEncrypting || isUploading || quotaExceeded}
                    onClick={handleFileUpload}
                    className={`w-full relative py-4 btn-primary rounded-lg font-mono font-bold uppercase tracking-wider text-xs flex items-center justify-center gap-2 active-glow disabled:opacity-50
                      ${isUploading || isEncrypting ? 'shadow-[0_0_30px_rgba(59,130,246,0.4)]' : ''}
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
              className="bg-bg-card p-6 rounded-xl technical-border"
            >
              <div className="flex flex-col items-center text-center mb-8">
                <div className="p-4 bg-green-500/10 rounded-full mb-4 shadow-[0_0_20px_rgba(34,197,94,0.1)]">
                  <Share2 className="w-10 h-10 text-green-500 filter drop-shadow-[0_0_8px_rgba(34,197,94,0.4)]" />
                </div>
                <h2 className="text-xl font-mono font-bold tracking-tight mb-2 uppercase text-text-main">Share Created</h2>
                <p className="text-xs text-text-sub">Your secure link is ready for delivery.</p>
              </div>

              <div className="space-y-4">
                <div className="bg-bg-base/40 p-3 rounded-lg border border-border-main flex items-center gap-3">
                  <div className="flex-1 overflow-hidden">
                    <p className="text-[10px] font-mono text-text-sub uppercase mb-1">Vault URI</p>
                    <p className="text-xs font-mono text-blue-400 truncate break-all">{generatedLink}</p>
                  </div>
                  <button 
                    onClick={() => copyToClipboard(generatedLink)}
                    className="p-2 hover:bg-black/5 rounded-md text-text-sub hover:text-text-main transition-colors"
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
                    className="py-3 text-[10px] font-mono font-bold tracking-wider uppercase bg-bg-base/5 hover:bg-bg-base/10 text-text-main rounded-lg transition-colors border border-border-main"
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
                <div className="mt-8 pt-8 border-t border-border-main">
                  <div className="flex items-center gap-2 mb-4">
                    <Send className="w-3 h-3 text-blue-500" />
                    <span className="text-[10px] font-mono font-bold text-text-main uppercase tracking-widest">Direct Share (In-App)</span>
                  </div>
                  <p className="text-[10px] text-text-sub mb-4 font-mono lowercase">Send this file directly to another CipherVault user's inbox.</p>
                  
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Search className="w-3 h-3 text-text-sub" />
                      </div>
                      <input 
                        id="recipientInput"
                        placeholder="Recipient username..."
                        className="w-full bg-bg-base/40 border border-border-main focus:border-blue-500/30 rounded-lg py-2 pl-9 pr-3 text-[10px] font-mono text-text-main placeholder:text-text-sub outline-none transition-all"
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
                          setError(`[DIRECT SUCCESS] Securely shared with @${name}`);
                          setTimeout(() => setError(null), 3000);
                        }
                      }}
                      className="px-4 bg-bg-base/5 hover:bg-bg-base/10 text-text-main rounded-lg border border-border-main transition-all"
                    >
                      <Check className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Private Key Integration */}
                <div className="mt-8 pt-8 border-t border-border-main">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <Key className="w-3 h-3 text-blue-500" />
                      <span className="text-[10px] font-mono font-bold text-text-main uppercase tracking-widest">Bond to Private Key</span>
                    </div>
                    {profile && (
                      <span className="text-[8px] font-mono text-blue-500/60 uppercase">{(profile.privateKeys?.length || 0)}/5 Regs</span>
                    )}
                  </div>

                  {!profile ? (
                    <div className="p-4 bg-blue-500/5 rounded-xl border border-blue-500/10 text-center">
                      <p className="text-[9px] font-mono text-text-sub uppercase">Sign in to manage and bond private keys</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 gap-2">
                        {profile.privateKeys && profile.privateKeys.length > 0 ? (
                          profile.privateKeys.map((key, i) => (
                            <div key={i} className="space-y-1">
                              {editingKeyIndex === i ? (
                                <div className="flex gap-2">
                                  <input 
                                    type="text"
                                    value={editValue}
                                    onChange={(e) => setEditValue(e.target.value.substring(0, 20))}
                                    className="flex-1 bg-bg-base/40 border border-blue-500/30 rounded-lg p-2 text-[10px] font-mono text-blue-400 outline-none"
                                  />
                                  <button onClick={() => editPersonalKey(key, editValue)} className="p-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors">
                                    <Check className="w-3 h-3" />
                                  </button>
                                  <button onClick={() => setEditingKeyIndex(null)} className="p-2 bg-white/5 text-slate-500 rounded-lg hover:text-white transition-colors">
                                    <X className="w-3 h-3" />
                                  </button>
                                </div>
                              ) : (
                                <div className="group flex items-center gap-2">
                                  <button
                                    onClick={() => bindShareToKey(key)}
                                    disabled={isResolvingKey}
                                    className="flex-1 p-3 bg-bg-base/40 border border-border-main hover:border-blue-500/30 rounded-lg transition-all text-left flex items-center justify-between"
                                  >
                                    <div className="flex items-center gap-3">
                                      <div className="p-1.5 bg-blue-500/10 rounded group-hover:bg-blue-500/20 transition-colors">
                                        <Fingerprint className="w-3 h-3 text-blue-500" />
                                      </div>
                                      <span className="text-[10px] font-mono text-text-main font-bold truncate max-w-[120px]">{key}</span>
                                    </div>
                                    <ChevronRight className="w-3 h-3 text-text-sub group-hover:text-blue-500 transition-all opacity-0 group-hover:opacity-100" />
                                  </button>
                                  <div className="flex flex-col gap-1 opacity-0 group-hover:opacity-100 transition-all">
                                    <button 
                                      onClick={() => { setEditingKeyIndex(i); setEditValue(key); }}
                                      className="p-1.5 hover:bg-white/5 text-slate-500 hover:text-blue-400 transition-colors rounded"
                                    >
                                      <Edit className="w-3 h-3" />
                                    </button>
                                    <button 
                                      onClick={() => deletePersonalKey(key)}
                                      className="p-1.5 hover:bg-white/5 text-slate-500 hover:text-red-400 transition-colors rounded"
                                    >
                                      <Trash2 className="w-3 h-3" />
                                    </button>
                                  </div>
                                </div>
                              )}
                            </div>
                          ))
                        ) : (
                          <div className="p-4 bg-bg-base/20 border border-dashed border-border-main rounded-xl text-center">
                            <p className="text-[9px] font-mono text-text-sub uppercase">No keys registered in your vault spectrum</p>
                          </div>
                        )}
                      </div>

                      {/* Custom Key Registration */}
                      {(!profile.privateKeys || profile.privateKeys.length < 5) && (
                        <div className="pt-2 space-y-2">
                          <div className="relative">
                            <input 
                              type="text"
                              value={customKeyInput}
                              onChange={(e) => setCustomKeyInput(e.target.value.substring(0, 20))}
                              placeholder="Create custom key (12-20 chars)..."
                              className="w-full bg-bg-base/40 border border-border-main focus:border-blue-500/30 rounded-lg py-2.5 px-3 text-[10px] font-mono text-text-main placeholder:text-text-sub outline-none transition-all pr-12"
                            />
                            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                               <span className={`text-[8px] font-mono ${(customKeyInput.length >= 12 && customKeyInput.length <= 20) ? 'text-blue-500' : 'text-slate-500'}`}>
                                 {customKeyInput.length}C
                               </span>
                            </div>
                          </div>
                          <button
                            onClick={() => createPersonalKey(customKeyInput)}
                            disabled={customKeyInput.length < 12 || customKeyInput.length > 20}
                            className="w-full py-2.5 bg-blue-600/10 hover:bg-blue-600/20 text-blue-500 border border-blue-500/30 rounded-lg text-[9px] font-mono font-bold uppercase tracking-widest transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                          >
                            <Zap className="w-3 h-3" />
                            Register Terminal Key
                          </button>
                        </div>
                      )}
                    </div>
                  )}
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
              className="bg-bg-card p-6 rounded-xl technical-border"
            >
              <h2 className="text-lg font-mono font-bold flex items-center gap-2 mb-6 text-text-main">
                <Unlock className="w-4 h-4 text-blue-500" />
                SECURE ACCESS
              </h2>

              {error ? (
                <div className="flex flex-col items-center text-center p-8 bg-red-500/5 border border-red-500/10 rounded-xl">
                  <AlertCircle className="w-12 h-12 text-red-500/30 mb-4" />
                  <h3 className="text-red-400 font-bold mb-2 uppercase">Access_Denied</h3>
                  <p className="text-xs text-text-sub mb-6">{error}</p>
                  <button onClick={reset} className="text-xs font-mono uppercase text-text-sub hover:text-text-main underline underline-offset-4">Return Home</button>
                </div>
              ) : !targetShare ? (
                <div className="flex flex-col items-center py-12">
                  <Loader2 className="w-8 h-8 animate-spin text-blue-500/30" />
                  <p className="mt-4 text-xs font-mono text-text-sub uppercase tracking-widest">Verifying Handshake...</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {targetSenderHandle && (
                    <div className="flex items-center gap-2 mb-2 p-2 bg-blue-500/5 rounded-lg border border-blue-500/10">
                      <UserIcon className="w-3 h-3 text-blue-400" />
                      <span className="text-[10px] font-mono font-bold text-blue-400 uppercase tracking-widest">Relayed by @{targetSenderHandle}</span>
                    </div>
                  )}
                  <div className="flex items-center gap-4 bg-bg-base/30 p-4 rounded-xl border border-border-main">
                    {getFileIcon(targetShare.mimeType)}
                    <div className="flex-1 overflow-hidden">
                      <p className="text-sm font-bold text-text-main truncate">{targetShare.fileName}</p>
                      <div className="flex items-center gap-2 text-[10px] font-mono text-text-sub uppercase mt-1">
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
                      className={`relative py-4 btn-primary rounded-lg font-mono font-bold uppercase tracking-wider text-[10px] flex items-center justify-center gap-2 active-glow disabled:opacity-50
                        ${isDecrypting ? 'shadow-[0_0_30px_rgba(59,130,246,0.4)]' : 'shadow-lg shadow-blue-500/10'}
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
                      className={`relative py-4 btn-primary rounded-lg font-mono font-bold uppercase tracking-wider text-[10px] flex items-center justify-center gap-2 active-glow disabled:opacity-50
                        ${isDecrypting ? 'shadow-[0_0_30px_rgba(59,130,246,0.4)]' : 'shadow-lg shadow-blue-500/20'}
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
              text={decryptedMessage.text}
              sender={decryptedMessage.sender}
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
            <span className="text-[8px] font-mono text-text-sub uppercase tracking-[0.4em] opacity-50 group-hover:opacity-100 transition-opacity">Designed & Developed by</span>
            <div className="flex items-center gap-3">
              <div className="h-[1px] w-4 bg-gradient-to-r from-transparent to-border-main" />
              <span className="text-sm font-mono font-black text-text-sub tracking-[0.5em] uppercase hover:text-blue-500 transition-colors cursor-default">GM Studio</span>
              <div className="h-[1px] w-4 bg-gradient-to-l from-transparent to-border-main" />
            </div>
          </div>

          <p className="text-[10px] font-mono text-text-sub uppercase tracking-widest flex items-center justify-center gap-2 opacity-60">
            <span>AES-256-GCM</span>
            <span>•</span>
            <span>End-to-End Encrypted</span>
          </p>
        </footer>
      </main>
      </div>
    </>
  );
}
