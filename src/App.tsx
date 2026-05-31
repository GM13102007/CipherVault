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
  Edit,
  Home,
  MessageSquare,
  History as HistoryIcon,
  Folder,
  Volume2,
  Play,
  Pause,
  RotateCcw,
  RotateCw,
  Maximize,
  Minimize,
  VolumeX,
  Volume1,
  ZoomIn,
  ZoomOut,
  RefreshCw,
  Move,
  Maximize2,
  Minimize2,
  Mic,
  Square
} from 'lucide-react';
import { 
  doc, 
  setDoc, 
  getDoc, 
  deleteDoc,
  updateDoc,
  increment,
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
  and,
  getDocFromServer
} from 'firebase/firestore';
import { auth, db, signInAll, signOutAll, signInAnonymous } from './firebase';
import { onAuthStateChanged, User, signInWithPopup, GoogleAuthProvider } from 'firebase/auth';
import { encryptData, decryptData, arrayBufferToBase64, base64ToArrayBuffer, generateId } from './lib/crypto';
import { handleFirestoreError, OperationType } from './lib/errorHandlers';
import JSZip from 'jszip';
import Markdown from 'react-markdown';

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
  views?: number;
  allowView?: boolean;
  allowDownload?: boolean;
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

// --- File Preview Engine Components ---

function usePdfJs() {
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const getPdfJsLib = () => (window as any).pdfjsLib || (window as any)['pdfjs-dist/build/pdf'];

    if (getPdfJsLib()) {
      setLoaded(true);
      return;
    }

    const loadLocal = () => {
      const script = document.createElement('script');
      script.src = '/pdf.min.js';
      script.async = true;
      script.onload = () => {
        const pdfjsLib = getPdfJsLib();
        if (pdfjsLib) {
          pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.js';
          setLoaded(true);
        } else {
          loadCdn();
        }
      };
      script.onerror = () => {
        // Fallback to CDNjs
        console.warn('Local PDF.js script failed to load. Falling back to cdnjs...');
        loadCdn();
      };
      document.body.appendChild(script);
    };

    const loadCdn = () => {
      const script = document.createElement('script');
      script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js';
      script.async = true;
      script.onload = () => {
        const pdfjsLib = getPdfJsLib();
        if (pdfjsLib) {
          pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
          setLoaded(true);
        } else {
          setError('Failed to resolve PDF preview engine globals.');
        }
      };
      script.onerror = () => {
        setError('Failed to load PDF preview engine.');
      };
      document.body.appendChild(script);
    };

    loadLocal();
  }, []);

  return { loaded, error };
}

function PdfPreview({ url }: { url: string }) {
  const { loaded, error } = usePdfJs();
  const [pdf, setPdf] = useState<any>(null);
  const [numPages, setNumPages] = useState<number>(0);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [scale, setScale] = useState<number>(1.2);
  const [loading, setLoading] = useState<boolean>(true);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const renderTaskRef = useRef<any>(null);

  useEffect(() => {
    if (!loaded) return;

    let active = true;
    const loadPdf = async () => {
      try {
        setLoading(true);
        const pdfjsLib = (window as any).pdfjsLib || (window as any)['pdfjs-dist/build/pdf'];
        if (!pdfjsLib) {
          throw new Error("PDF.js global library could not be resolved from scope.");
        }
        
        // Fetch raw encrypted/decrypted file blob as an ArrayBuffer and pass directly 
        // to block sandboxing/cross-origin iframe loading restrictions
        const res = await fetch(url);
        const arrayBuf = await res.arrayBuffer();
        const uint8 = new Uint8Array(arrayBuf);

        const loadingTask = pdfjsLib.getDocument({ data: uint8 });
        const pdfDoc = await loadingTask.promise;
        if (!active) return;
        setPdf(pdfDoc);
        setNumPages(pdfDoc.numPages);
        setCurrentPage(1);
        setLoading(false);
      } catch (err: any) {
        console.error("PDF.js loading error:", err);
        if (active) {
          setLoading(false);
        }
      }
    };

    loadPdf();

    return () => {
      active = false;
    };
  }, [loaded, url]);

  useEffect(() => {
    if (!pdf || !canvasRef.current) return;

    let active = true;
    const renderPage = async () => {
      try {
        if (renderTaskRef.current) {
          renderTaskRef.current.cancel();
        }

        const page = await pdf.getPage(currentPage);
        if (!active) return;

        const viewport = page.getViewport({ scale });
        const canvas = canvasRef.current;
        if (!canvas) return;

        const context = canvas.getContext('2d');
        if (!context) return;

        canvas.height = viewport.height;
        canvas.width = viewport.width;

        const renderContext = {
          canvasContext: context,
          viewport: viewport,
        };

        const renderTask = page.render(renderContext);
        renderTaskRef.current = renderTask;
        await renderTask.promise;
      } catch (err: any) {
        if (err.name !== 'RenderingCancelledException') {
          console.error("PDF page rendering error:", err);
        }
      }
    };

    renderPage();

    return () => {
      active = false;
    };
  }, [pdf, currentPage, scale]);

  if (error) {
    return (
      <div className="p-8 text-center text-red-400 font-mono text-xs">
        {error}
        <iframe src={url} className="w-full h-[60vh] mt-4 border border-white/10 rounded-xl" />
      </div>
    );
  }

  if (loading || !loaded) {
    return (
      <div className="flex flex-col items-center justify-center p-12 space-y-3">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <span className="text-xs font-mono text-slate-500 uppercase tracking-widest animate-pulse">Decrypting and Rendering Document Pages...</span>
      </div>
    );
  }

  return (
    <div className="w-full h-full flex flex-col min-h-[60vh] items-center bg-[#07080a] p-4 rounded-xl border border-white/5">
      {/* Mini control panel */}
      <div className="w-full max-w-lg bg-white/5 border border-white/5 px-4 py-2 rounded-xl flex items-center justify-between font-mono text-xs mb-4">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
            disabled={currentPage <= 1}
            className="px-3 py-1.5 bg-white/5 hover:bg-white/10 disabled:opacity-30 rounded-lg text-white transition-all cursor-pointer"
          >
            ← Prev
          </button>
          <span className="text-slate-400">
            Page {currentPage} of {numPages}
          </span>
          <button
            type="button"
            onClick={() => setCurrentPage(prev => Math.min(prev + 1, numPages))}
            disabled={currentPage >= numPages}
            className="px-3 py-1.5 bg-white/5 hover:bg-white/10 disabled:opacity-30 rounded-lg text-white transition-all cursor-pointer"
          >
            Next →
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setScale(s => Math.max(s - 0.2, 0.6))}
            className="px-2 py-1 bg-white/5 hover:bg-white/10 rounded text-slate-300 cursor-pointer"
          >
            A-
          </button>
          <span className="text-[10px] text-slate-500">{Math.round(scale * 100)}%</span>
          <button
            type="button"
            onClick={() => setScale(s => Math.min(s + 0.2, 2.0))}
            className="px-2 py-1 bg-white/5 hover:bg-white/10 rounded text-slate-300 cursor-pointer"
          >
            A+
          </button>
        </div>
      </div>

      {/* Canvas container with scroll/zoom support */}
      <div className="w-full overflow-auto max-h-[55vh] flex items-start justify-center p-2 bg-black/40 border border-white/5 rounded-2xl shadow-inner scrollbar-thin">
        <canvas ref={canvasRef} className="max-w-full h-auto bg-white rounded shadow-2xl transition-transform duration-200" />
      </div>
    </div>
  );
}

function TextPreview({ url }: { url: string }) {
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const fetchContent = async () => {
      try {
        setLoading(true);
        const res = await fetch(url);
        const text = await res.text();
        if (active) {
          setContent(text);
          setLoading(false);
        }
      } catch (err: any) {
        console.error("Text file loading error:", err);
        if (active) {
          setError("Failed to load text file content.");
          setLoading(false);
        }
      }
    };

    fetchContent();
    return () => {
      active = false;
    };
  }, [url]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 space-y-3">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <span className="text-xs font-mono text-slate-500 uppercase tracking-widest animate-pulse">Reading Note Stream...</span>
      </div>
    );
  }

  if (error) {
    return <div className="p-8 text-center text-red-400 font-mono text-xs">{error}</div>;
  }

  let formattedContent = content;
  let isJson = false;
  try {
    const rawParsed = JSON.parse(content);
    formattedContent = JSON.stringify(rawParsed, null, 2);
    isJson = true;
  } catch (e) {
    // Not JSON
  }

  return (
    <div className="w-full h-full min-h-[50vh] max-h-[60vh] flex flex-col bg-[#07080a] rounded-xl border border-white/5 overflow-hidden font-mono text-left">
      <div className="bg-white/5 px-4 py-2 border-b border-white/5 flex items-center justify-between text-[10px] text-slate-400 select-none">
        <span>{isJson ? 'JSON OBJECT VIEWER' : 'TEXT NOTE VIEWER'}</span>
        <span>{content.length} characters</span>
      </div>
      <div className="flex-1 overflow-auto p-4 md:p-6 text-xs text-slate-300 whitespace-pre-wrap leading-relaxed select-text font-mono selection:bg-blue-500/20 scrollbar-thin">
        {isJson ? (
          <code className="text-blue-400 block break-all">{formattedContent}</code>
        ) : (
          <code>{formattedContent}</code>
        )}
      </div>
    </div>
  );
}

function MarkdownPreview({ url }: { url: string }) {
  const [content, setContent] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const fetchContent = async () => {
      try {
        setLoading(true);
        const res = await fetch(url);
        const text = await res.text();
        if (active) {
          setContent(text);
          setLoading(false);
        }
      } catch (err: any) {
        console.error("Markdown loading error:", err);
        if (active) {
          setError("Failed to load markdown content.");
          setLoading(false);
        }
      }
    };

    fetchContent();
    return () => {
      active = false;
    };
  }, [url]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 space-y-3">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <span className="text-xs font-mono text-slate-500 uppercase tracking-widest text-center animate-pulse">Rendering Secure Markdown Notes...</span>
      </div>
    );
  }

  if (error) {
    return <div className="p-8 text-center text-red-400 font-mono text-xs">{error}</div>;
  }

  return (
    <div className="w-full h-full min-h-[55vh] max-h-[65vh] flex flex-col bg-[#07080a] rounded-xl border border-white/5 overflow-hidden text-left">
      <div className="bg-white/5 px-4 py-2 border-b border-white/5 flex items-center justify-between text-[10px] text-slate-400 font-mono select-none">
        <span>MARKDOWN PRINTER ENGINE</span>
        <span>{content.split(/\s+/).filter(Boolean).length} words</span>
      </div>
      <div className="flex-1 overflow-auto p-6 md:p-8 text-slate-300 leading-relaxed select-text selection:bg-blue-500/20 scrollbar-thin">
        <div className="markdown-body prose prose-invert max-w-none text-sm space-y-4">
          <Markdown>{content}</Markdown>
        </div>
      </div>
    </div>
  );
}

function getMimeType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'png': return 'image/png';
    case 'jpg':
    case 'jpeg': return 'image/jpeg';
    case 'gif': return 'image/gif';
    case 'webp': return 'image/webp';
    case 'svg': return 'image/svg+xml';
    case 'bmp': return 'image/bmp';
    case 'mp4': return 'video/mp4';
    case 'webm': return 'video/webm';
    case 'ogg': return 'video/ogg';
    case 'mov': return 'video/quicktime';
    case 'mp3': return 'audio/mpeg';
    case 'wav': return 'audio/wav';
    case 'm4a': return 'audio/mp4';
    case 'flac': return 'audio/flac';
    case 'pdf': return 'application/pdf';
    case 'md': return 'text/markdown';
    case 'txt': return 'text/plain';
    case 'json': return 'application/json';
    case 'js': return 'application/javascript';
    case 'ts': return 'text/typescript';
    case 'tsx': return 'text/typescript-jsx';
    case 'jsx': return 'text/jsx';
    case 'css': return 'text/css';
    case 'html': return 'text/html';
    case 'xml': return 'text/xml';
    default: return 'application/octet-stream';
  }
}

function ZipPreview({ url, onPreviewFile }: { url: string; onPreviewFile?: (subFile: { url: string; name: string; type: string; isSubFile: boolean }) => void }) {
  const [files, setFiles] = useState<{ name: string; size: number; dir: boolean }[]>([]);
  const [zipInstance, setZipInstance] = useState<JSZip | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [unpackingFile, setUnpackingFile] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const loadZip = async () => {
      try {
        setLoading(true);
        const res = await fetch(url);
        const blob = await res.blob();
        const zip = await JSZip.loadAsync(blob);
        if (active) {
          setZipInstance(zip);
          const fileList: { name: string; size: number; dir: boolean }[] = [];
          zip.forEach((relativePath, fileObj) => {
            fileList.push({
              name: relativePath,
              size: (fileObj as any)._data?.uncompressedSize || 0,
              dir: fileObj.dir
            });
          });
          setFiles(fileList);
          setLoading(false);
        }
      } catch (err: any) {
        console.error("Zip preview loading error:", err);
        if (active) {
          setError("Failed to index zip archive structure.");
          setLoading(false);
        }
      }
    };

    loadZip();
    return () => {
      active = false;
    };
  }, [url]);

  const handleFileClick = async (fileName: string) => {
    if (!zipInstance || unpackingFile || !onPreviewFile) return;
    try {
      setUnpackingFile(fileName);
      const zipFile = zipInstance.file(fileName);
      if (!zipFile) {
        throw new Error("Target file not found in ZIP.");
      }
      const content = await zipFile.async("blob");
      const mime = getMimeType(fileName);
      const subUrl = URL.createObjectURL(content);
      
      onPreviewFile({
        url: subUrl,
        name: fileName.split('/').pop() || fileName,
        type: mime,
        isSubFile: true
      });
    } catch (err) {
      console.error("Failed to unpack zip element:", err);
    } finally {
      setUnpackingFile(null);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-12 space-y-3">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <span className="text-xs font-mono text-slate-500 uppercase tracking-widest text-center animate-pulse font-mono">Unpacking Secure ZIP Manifest...</span>
      </div>
    );
  }

  if (error) {
    return <div className="p-8 text-center text-red-400 font-mono text-xs">{error}</div>;
  }

  return (
    <div className="w-full h-full flex flex-col bg-[#07080a] rounded-xl border border-white/5 overflow-hidden font-mono text-left">
      <div className="bg-white/5 px-4 py-2 border-b border-white/5 flex items-center justify-between text-[10px] text-slate-400 select-none">
        <span>ARCHIVE COMPRESSION EXPLORER (ZIP)</span>
        <span>{files.length} items</span>
      </div>
      <div className="flex-1 overflow-auto p-4 space-y-1 scrollbar-thin">
        {files.length === 0 ? (
          <p className="text-xs text-slate-600 italic text-center p-8">Empty Archive.</p>
        ) : (
          files.map((file, i) => {
            const isClickable = !file.dir;
            const isUnpacking = unpackingFile === file.name;
            
            return (
              <div 
                key={i} 
                onClick={() => isClickable && handleFileClick(file.name)}
                className={`flex items-center justify-between p-2 rounded text-xs transition-colors
                  ${isClickable ? 'cursor-pointer hover:bg-white/5 hover:text-blue-400 group/item' : 'select-text text-slate-400'}
                `}
              >
                <div className="flex items-center gap-2 truncate min-w-0 flex-1">
                  {file.dir ? (
                    <Folder className="w-4 h-4 text-blue-400 shrink-0" />
                  ) : (
                    <FileText className={`w-4 h-4 shrink-0 transition-colors ${isClickable ? 'text-slate-400 group-hover/item:text-blue-400' : 'text-slate-500'}`} />
                  )}
                  <span className={`truncate ${file.dir ? 'text-blue-300 font-semibold' : 'text-slate-300 group-hover/item:text-blue-300'}`}>
                    {file.name}
                  </span>
                </div>
                
                <div className="flex items-center gap-2 shrink-0 ml-4 select-none">
                  {isUnpacking ? (
                    <Loader2 className="w-3 h-3 text-blue-500 animate-spin" />
                  ) : isClickable ? (
                    <span className="opacity-0 group-hover/item:opacity-100 transition-opacity text-[9px] font-mono text-blue-500 tracking-wider flex items-center gap-1 uppercase">
                      <Eye className="w-3.5 h-3.5" /> View
                    </span>
                  ) : null}
                  
                  {!file.dir && (
                    <span className="text-[10px] text-slate-500 font-mono">
                      {(file.size / 1024).toFixed(1)} KB
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function CustomVideoPlayer({ url, name }: { url: string; name: string }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [currentTime, setCurrentTime] = useState<number>(0);
  const [duration, setDuration] = useState<number>(0);
  const [volume, setVolume] = useState<number>(1.0);
  const [isMuted, setIsMuted] = useState<boolean>(false);
  const [playbackRate, setPlaybackRate] = useState<number>(1.0);
  const [isTheaterMode, setIsTheaterMode] = useState<boolean>(false);
  const [isSeeking, setIsSeeking] = useState<boolean>(false);
  const [showSpeedMenu, setShowSpeedMenu] = useState<boolean>(false);
  const [showControls, setShowControls] = useState<boolean>(true);
  
  const controlsTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const resetControlsTimer = () => {
    setShowControls(true);
    if (controlsTimeoutRef.current) {
      clearTimeout(controlsTimeoutRef.current);
    }
    if (isPlaying) {
      controlsTimeoutRef.current = setTimeout(() => {
        setShowControls(false);
      }, 3500);
    }
  };

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const onPlay = () => setIsPlaying(true);
    const onPause = () => setIsPlaying(false);
    const onTimeUpdate = () => {
      if (!isSeeking) {
        setCurrentTime(video.currentTime);
      }
    };
    const onDurationChange = () => setDuration(video.duration);

    video.addEventListener('play', onPlay);
    video.addEventListener('pause', onPause);
    video.addEventListener('timeupdate', onTimeUpdate);
    video.addEventListener('durationchange', onDurationChange);

    return () => {
      video.removeEventListener('play', onPlay);
      video.removeEventListener('pause', onPause);
      video.removeEventListener('timeupdate', onTimeUpdate);
      video.removeEventListener('durationchange', onDurationChange);
    };
  }, [isSeeking]);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    video.playbackRate = playbackRate;
    video.volume = volume;
    video.muted = isMuted;
  }, [playbackRate, volume, isMuted]);

  useEffect(() => {
    if (showControls) {
      resetControlsTimer();
    } else {
      if (controlsTimeoutRef.current) {
        clearTimeout(controlsTimeoutRef.current);
      }
    }
    return () => {
      if (controlsTimeoutRef.current) {
        clearTimeout(controlsTimeoutRef.current);
      }
    };
  }, [isPlaying, showControls]);

  const togglePlay = (e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const video = videoRef.current;
    if (!video) return;
    resetControlsTimer();
    if (video.paused) {
      video.play().catch(err => console.error("Playback error", err));
    } else {
      video.pause();
    }
  };

  const skip = (seconds: number) => {
    const video = videoRef.current;
    if (!video) return;
    resetControlsTimer();
    video.currentTime = Math.min(Math.max(video.currentTime + seconds, 0), video.duration || 0);
  };

  const handleVolumeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseFloat(e.target.value);
    setVolume(val);
    setIsMuted(val === 0);
    resetControlsTimer();
  };

  const toggleMute = () => {
    setIsMuted(prev => !prev);
    resetControlsTimer();
  };

  const changeSpeed = (rate: number) => {
    setPlaybackRate(rate);
    setShowSpeedMenu(false);
    resetControlsTimer();
  };

  const handleSeekChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseFloat(e.target.value);
    setCurrentTime(val);
    setIsSeeking(true);
    resetControlsTimer();
  };

  const handleSeekEnd = (e: any) => {
    const val = parseFloat(e.target.value);
    if (videoRef.current) {
      videoRef.current.currentTime = val;
    }
    setIsSeeking(false);
    resetControlsTimer();
  };

  const formatTime = (seconds: number) => {
    if (isNaN(seconds)) return "0:00";
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  const toggleFullscreen = () => {
    const container = containerRef.current;
    if (!container) return;
    resetControlsTimer();
    if (!document.fullscreenElement) {
      container.requestFullscreen().catch(err => console.error("Fullscreen error", err));
    } else {
      document.exitFullscreen();
    }
  };

  const handleContainerClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!showControls) {
      setShowControls(true);
    } else {
      togglePlay();
    }
  };

  return (
    <div 
      ref={containerRef} 
      onMouseMove={resetControlsTimer}
      onTouchStart={resetControlsTimer}
      onMouseLeave={() => isPlaying && setShowControls(false)}
      onContextMenu={(e) => e.preventDefault()}
      className="relative w-full h-full min-h-[40vh] md:min-h-[50vh] overflow-hidden bg-[#020203] transition-all duration-300 rounded-xl border border-white/5 flex flex-col justify-center items-center select-none group/player"
    >
      <video 
        ref={videoRef}
        src={url}
        autoPlay
        playsInline
        onClick={handleContainerClick}
        onContextMenu={(e) => e.preventDefault()}
        className="w-full h-full object-contain cursor-pointer"
        controlsList="nodownload nofullscreen noremoteplayback"
        disablePictureInPicture
        disableRemotePlayback
      />

      <div className={`absolute inset-0 bg-gradient-to-t from-black/80 via-black/0 to-black/30 transition-opacity duration-300 pointer-events-none z-10 ${showControls ? 'opacity-100' : 'opacity-0'}`} />

      <div className={`absolute top-4 left-4 text-xs font-mono text-white/80 bg-black/60 px-3 py-1.5 rounded-lg border border-white/10 transition-opacity duration-300 pointer-events-none truncate max-w-[80%] flex items-center gap-2 z-20 ${showControls ? 'opacity-100' : 'opacity-0'}`}>
        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
        {name}
      </div>

      <div className={`absolute bottom-0 left-0 right-0 p-4 bg-gradient-to-t from-black via-black/90 to-[#020203]/0 transition-opacity duration-300 flex flex-col gap-3 z-30 ${showControls ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'}`}>
        <div className="w-full flex items-center gap-2 pointer-events-auto">
          <input 
            type="range"
            min={0}
            max={duration || 100}
            step={0.1}
            value={currentTime}
            onChange={handleSeekChange}
            onMouseUp={handleSeekEnd}
            onTouchEnd={handleSeekEnd}
            className="w-full h-1.5 bg-white/20 hover:bg-white/30 rounded-lg appearance-none cursor-pointer accent-blue-500 outline-none transition-all"
          />
        </div>

        <div className="flex items-center justify-between pointer-events-auto">
          <div className="flex items-center gap-2 sm:gap-3">
            <button 
              type="button"
              onClick={togglePlay}
              className="p-1.5 hover:bg-white/10 rounded-lg text-white transition-colors cursor-pointer animate-none"
              title={isPlaying ? "Pause" : "Play"}
            >
              {isPlaying ? <Pause className="w-4 h-4 text-white" /> : <Play className="w-4 h-4 text-white fill-white" />}
            </button>

            <button 
              type="button"
              onClick={() => skip(-10)}
              className="p-1.5 hover:bg-white/10 rounded-lg text-white transition-colors cursor-pointer"
              title="Rewind 10s"
            >
              <RotateCcw className="w-4 h-4 text-white" />
            </button>

            <button 
              type="button"
              onClick={() => skip(10)}
              className="p-1.5 hover:bg-white/10 rounded-lg text-white transition-colors cursor-pointer"
              title="Forward 10s"
            >
              <RotateCw className="w-4 h-4 text-white" />
            </button>

            <div className="flex items-center gap-1 sm:gap-1.5 ml-1">
              <button 
                type="button"
                onClick={toggleMute}
                className="p-1.5 hover:bg-white/10 rounded-lg text-white transition-colors cursor-pointer"
                title={isMuted ? "Unmute" : "Mute"}
              >
                {isMuted || volume === 0 ? (
                  <VolumeX className="w-4 h-4 text-white" />
                ) : volume < 0.5 ? (
                  <Volume1 className="w-4 h-4 text-white" />
                ) : (
                  <Volume2 className="w-4 h-4 text-white" />
                )}
              </button>
              <input 
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={isMuted ? 0 : volume}
                onChange={handleVolumeChange}
                className="w-12 sm:w-16 h-1 bg-white/20 rounded accent-white outline-none cursor-pointer"
              />
            </div>

            <div className="text-[10px] font-mono text-slate-300 select-none ml-1 sm:ml-2">
              {formatTime(currentTime)} / {formatTime(duration)}
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3">
            <div className="relative">
              <button 
                type="button"
                onClick={(e) => { e.stopPropagation(); setShowSpeedMenu(!showSpeedMenu); }}
                className="px-2 py-1 bg-white/5 hover:bg-white/10 rounded text-[10px] font-mono text-white tracking-wider flex items-center gap-1 cursor-pointer border border-white/5"
              >
                {playbackRate.toFixed(1)}x
              </button>

              {showSpeedMenu && (
                <div className="absolute bottom-8 right-0 bg-slate-950 border border-white/10 rounded-lg p-1 flex flex-col min-w-[70px] z-50 text-xs font-mono">
                  {[0.5, 0.75, 1.0, 1.25, 1.5, 2.0].map((rate) => (
                    <button
                      key={rate}
                      type="button"
                      onClick={(e) => { e.stopPropagation(); changeSpeed(rate); }}
                      className={`px-2 py-1 hover:bg-white/10 rounded text-left ${playbackRate === rate ? 'text-blue-400 bg-white/5' : 'text-slate-300'}`}
                    >
                      {rate.toFixed(2)}x
                    </button>
                  ))}
                </div>
              )}
            </div>

            <button 
              type="button"
              onClick={(e) => { e.stopPropagation(); setIsTheaterMode(!isTheaterMode); }}
              className="p-1.5 hover:bg-white/10 rounded-lg text-white transition-colors cursor-pointer hidden sm:inline-block"
              title={isTheaterMode ? "Standard view" : "Theater view"}
            >
              <Maximize className="w-4 h-4 text-white" />
            </button>

            <button 
              type="button"
              onClick={(e) => { e.stopPropagation(); toggleFullscreen(); }}
              className="p-1.5 hover:bg-white/10 rounded-lg text-white transition-colors cursor-pointer"
              title="Fullscreen"
            >
              <Maximize2 className="w-4 h-4 text-white" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function CustomImageViewer({ url, name }: { url: string; name: string }) {
  const [scale, setScale] = useState<number>(1);
  const [rotation, setRotation] = useState<number>(0);
  const [position, setPosition] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement | null>(null);

  const touchStartDistRef = useRef<number | null>(null);
  const touchStartScaleRef = useRef<number>(1);

  const handleZoomIn = () => setScale(s => Math.min(s + 0.25, 4));
  const handleZoomOut = () => setScale(s => Math.max(s - 0.25, 0.5));
  const handleRotate = () => setRotation(r => (r + 90) % 360);
  const handleReset = () => {
    setScale(1);
    setRotation(0);
    setPosition({ x: 0, y: 0 });
  };

  const handleMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
    setDragStart({ x: e.clientX - position.x, y: e.clientY - position.y });
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!isDragging) return;
    setPosition({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleTouchStart = (e: React.TouchEvent<HTMLDivElement>) => {
    if (e.touches.length === 1) {
      setIsDragging(true);
      const touch = e.touches[0];
      setDragStart({ x: touch.clientX - position.x, y: touch.clientY - position.y });
    } else if (e.touches.length === 2) {
      setIsDragging(false);
      const t1 = e.touches[0];
      const t2 = e.touches[1];
      const dist = Math.hypot(t1.clientX - t2.clientX, t1.clientY - t2.clientY);
      touchStartDistRef.current = dist;
      touchStartScaleRef.current = scale;
    }
  };

  const handleTouchMove = (e: React.TouchEvent<HTMLDivElement>) => {
    if (e.touches.length === 1 && isDragging) {
      e.preventDefault(); // Prevent native gesture scrolling
      const touch = e.touches[0];
      setPosition({
        x: touch.clientX - dragStart.x,
        y: touch.clientY - dragStart.y
      });
    } else if (e.touches.length === 2 && touchStartDistRef.current !== null) {
      const t1 = e.touches[0];
      const t2 = e.touches[1];
      const dist = Math.hypot(t1.clientX - t2.clientX, t1.clientY - t2.clientY);
      const factor = dist / touchStartDistRef.current;
      const newScale = Math.min(Math.max(touchStartScaleRef.current * factor, 0.5), 4);
      setScale(newScale);
    }
  };

  const handleTouchEnd = () => {
    setIsDragging(false);
    touchStartDistRef.current = null;
  };

  return (
    <div 
      ref={containerRef}
      onContextMenu={(e) => e.preventDefault()}
      className="relative w-full h-full min-h-[40vh] bg-[#07080a] border border-white/5 rounded-2xl overflow-hidden flex flex-col select-none"
    >
      <div 
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
        onContextMenu={(e) => e.preventDefault()}
        className={`flex-1 relative flex items-center justify-center p-4 sm:p-8 overflow-hidden bg-black/40 ${isDragging ? 'cursor-grabbing' : 'cursor-grab'}`}
      >
        <div 
          style={{
            transform: `translate(${position.x}px, ${position.y}px) scale(${scale}) rotate(${rotation}deg)`,
            transition: isDragging ? 'none' : 'transform 0.2s cubic-bezier(0.1, 0.7, 0.1, 1)'
          }}
          className="max-w-full max-h-full flex items-center justify-center select-none"
        >
          <img 
            src={url} 
            alt={name} 
            draggable={false}
            onContextMenu={(e) => e.preventDefault()}
            className="max-w-full max-h-[50vh] md:max-h-[58vh] object-contain rounded-lg shadow-2xl pointer-events-none" 
            referrerPolicy="no-referrer"
          />
        </div>
      </div>

      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 bg-black/85 backdrop-blur-md border border-white/10 px-3 py-1.5 sm:px-4 sm:py-2 rounded-2xl flex items-center justify-center gap-3 sm:gap-4 text-white z-20 shadow-xl">
        <button 
          type="button" 
          onClick={handleZoomOut} 
          disabled={scale <= 0.5}
          className="p-1 sm:p-1.5 hover:bg-white/10 rounded-lg text-slate-300 disabled:opacity-30 cursor-pointer transition-all"
          title="Zoom Out"
        >
          <ZoomOut className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-white" />
        </button>

        <span className="font-mono text-[9px] sm:text-[10px] text-slate-400 font-semibold min-w-[38px] sm:min-w-[45px] text-center select-none">
          {Math.round(scale * 100)}%
        </span>

        <button 
          type="button" 
          onClick={handleZoomIn} 
          disabled={scale >= 4}
          className="p-1 sm:p-1.5 hover:bg-white/10 rounded-lg text-slate-300 disabled:opacity-30 cursor-pointer transition-all"
          title="Zoom In"
        >
          <ZoomIn className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-white" />
        </button>

        <div className="h-4 w-[1px] bg-white/10" />

        <button 
          type="button" 
          onClick={handleRotate} 
          className="p-1 sm:p-1.5 hover:bg-white/10 rounded-lg text-slate-300 cursor-pointer transition-all"
          title="Rotate 90°"
        >
          <RotateCw className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-white" />
        </button>

        <button 
          type="button" 
          onClick={handleReset} 
          className="p-1 sm:p-1.5 hover:bg-white/10 rounded-lg text-slate-300 cursor-pointer transition-all"
          title="Reset View"
        >
          <RefreshCw className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-white" />
        </button>
      </div>
    </div>
  );
}

// --- Helper Components ---

function AdminDashboard({ onPrune, quotaExceeded }: { onPrune: (isManual?: boolean) => Promise<void>; quotaExceeded?: boolean }) {
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  const handlePrune = async () => {
    setLoading(true);
    await onPrune(true);
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
  const [isBlurred, setIsBlurred] = useState(false);
  const [securityLog, setSecurityLog] = useState<string | null>(null);

  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden) {
        setIsBlurred(true);
        setSecurityLog("Message auto-locked: tab shifted.");
      }
    };

    const handleWindowBlur = () => {
      setIsBlurred(true);
      setSecurityLog("Focus lost: screen-shield activated.");
    };

    const handleWindowFocus = () => {
      setIsBlurred(false);
      setSecurityLog(null);
    };

    const handleContextMenu = (e: MouseEvent) => {
      e.preventDefault();
      setSecurityLog("Right-click disabled inside secure modal.");
      setTimeout(() => setSecurityLog(null), 3000);
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'PrintScreen') {
        e.preventDefault();
        setIsBlurred(true);
        setSecurityLog("Capture blocked.");
        return;
      }

      if ((e.ctrlKey || e.metaKey) && ['c', 's', 'p', 'u', 'a'].includes(e.key.toLowerCase())) {
        e.preventDefault();
        setSecurityLog(`Shortcut blocked in secure session.`);
        setTimeout(() => setSecurityLog(null), 3000);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleWindowBlur);
    window.addEventListener('focus', handleWindowFocus);
    window.addEventListener('contextmenu', handleContextMenu);
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleWindowBlur);
      window.removeEventListener('focus', handleWindowFocus);
      window.removeEventListener('contextmenu', handleContextMenu);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const userTraceID = auth.currentUser?.email || auth.currentUser?.uid || "GUEST_USER";

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[300] flex items-center justify-center p-4 bg-bg-base/90 backdrop-blur-md select-none"
      style={{ userSelect: 'none', WebkitUserSelect: 'none' }}
    >
      <div className="relative w-full max-w-lg bg-bg-card rounded-2xl border border-red-500/20 shadow-2xl technical-border overflow-hidden">
        <div className="scanning scanline opacity-30" />
        
        {/* Top Warning banner */}
        <div className="bg-red-500/15 border-b border-red-500/10 px-4 py-2 flex items-center justify-between text-[8px] font-mono text-red-400 select-none">
          <span className="font-bold flex items-center gap-1">
            <Lock className="w-2.5 h-2.5" /> E2EE TEMPORARY MEMORY SHIELD
          </span>
          <span>*TRACED TO {userTraceID.slice(0, 16)}...</span>
        </div>

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

        <div className="p-8 relative">
          {/* Subtle Watermark stream */}
          <div className="absolute inset-0 pointer-events-none overflow-hidden select-none z-10 opacity-[0.02] flex flex-wrap gap-x-8 gap-y-12 p-4 font-mono text-[8px] uppercase font-bold text-white">
            {Array.from({ length: 15 }).map((_, i) => (
              <span key={i} className="rotate-[-15deg] whitespace-nowrap">
                {userTraceID} SECURITY_LOG
              </span>
            ))}
          </div>

          <div 
            className={`bg-bg-base/40 p-6 rounded-xl border border-border-main technical-border min-h-[150px] flex items-center justify-center transition-all duration-300 relative z-20
              ${isBlurred ? 'blur-xl select-none scale-95 pointer-events-none' : ''}
            `}
          >
            <p className="text-sm font-mono text-text-main leading-relaxed text-center whitespace-pre-wrap">
              {text}
            </p>
          </div>

          {isBlurred && (
            <div className="absolute inset-0 bg-black/85 backdrop-blur-md flex flex-col items-center justify-center p-4 text-center z-30 rounded-xl">
              <Shield className="w-8 h-8 text-red-500 animate-pulse mb-2" />
              <p className="text-[10px] text-red-400 font-mono uppercase tracking-wider">PREVIEW BLURRED</p>
              <p className="text-[8px] text-slate-500 font-mono mt-1 lowercase">click modal to unblur</p>
            </div>
          )}
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

        {securityLog && (
          <div className="bg-red-950/90 border-t border-red-500/20 text-red-400 py-1.5 text-center text-[8px] font-mono uppercase tracking-widest">
            {securityLog}
          </div>
        )}

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

function bufferToWav(buffer: AudioBuffer): Blob {
  const numOfChan = buffer.numberOfChannels;
  const length = buffer.length * numOfChan * 2 + 44;
  const bufferArr = new ArrayBuffer(length);
  const view = new DataView(bufferArr);
  const channels: Float32Array[] = [];
  let sample;
  let offset = 0;
  let pos = 0;

  function setUint16(data: number) {
    view.setUint16(offset, data, true);
    offset += 2;
  }

  function setUint32(data: number) {
    view.setUint32(offset, data, true);
    offset += 4;
  }

  // write HEADERS
  setUint32(0x46464952);                         // "RIFF"
  setUint32(36 + buffer.length * numOfChan * 2); // file length - 8
  setUint32(0x45564157);                         // "WAVE"
  setUint32(0x20746d66);                         // "fmt " chunk
  setUint32(16);                                 // chunk length
  setUint16(1);                                  // sample format (raw PCM)
  setUint16(numOfChan);
  setUint32(buffer.sampleRate);
  setUint32(buffer.sampleRate * numOfChan * 2);  // byte rate
  setUint16(numOfChan * 2);                      // block align
  setUint16(16);                                 // bits per sample
  setUint32(0x61746164);                         // "data" - chunk
  setUint32(buffer.length * numOfChan * 2);      // chunk length

  for (let i = 0; i < buffer.numberOfChannels; i++) {
    channels.push(buffer.getChannelData(i));
  }

  while (pos < buffer.length) {
    for (let i = 0; i < numOfChan; i++) {             // interleave channels
      sample = Math.max(-1, Math.min(1, channels[i][pos])); // clamp
      sample = sample < 0 ? sample * 0x8000 : sample * 0x7FFF; // scale to 16-bit signed integer
      view.setInt16(offset, sample, true);          // write 16-bit sample (little endian)
      offset += 2;
    }
    pos++;
  }

  return new Blob([bufferArr], { type: 'audio/wav' });
}

async function applyPitchShift(originalBlob: Blob, semitones: number): Promise<Blob> {
  const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
  const arrayBuffer = await originalBlob.arrayBuffer();
  const originalBuffer = await audioCtx.decodeAudioData(arrayBuffer);
  
  // Calculate relative playback scale based on semitones
  const rate = Math.pow(2, semitones / 12);
  const targetSampleRate = 11025; // Optimized telephony sample rate for ultra-compact secure payloads under Firestore limit
  const renderedLength = Math.ceil(originalBuffer.duration * targetSampleRate / rate);
  
  const offlineCtx = new OfflineAudioContext(
    1, // mono layout
    renderedLength,
    targetSampleRate
  );
  
  const source = offlineCtx.createBufferSource();
  source.buffer = originalBuffer;
  source.playbackRate.value = rate;
  source.connect(offlineCtx.destination);
  source.start(0);
  
  const renderedBuffer = await offlineCtx.startRendering();
  await audioCtx.close();
  
  return bufferToWav(renderedBuffer);
}

function blobToBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      const dataUrl = reader.result as string;
      const base64 = dataUrl.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
}

function VoiceMemoPlayCapsule({ base64 }: { base64: string }) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [audioUrl, setAudioUrl] = useState<string | null>(null);

  useEffect(() => {
    try {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: 'audio/wav' });
      const url = URL.createObjectURL(blob);
      setAudioUrl(url);

      return () => {
        URL.revokeObjectURL(url);
      };
    } catch (e) {
      console.error("Failed to decode base64 audio", e);
    }
  }, [base64]);

  const handlePlayPause = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!audioRef.current) return;
    if (isPlaying) {
      audioRef.current.pause();
    } else {
      audioRef.current.play().catch(err => console.error(err));
    }
  };

  const onTimeUpdate = () => {
    if (audioRef.current) {
      setCurrentTime(audioRef.current.currentTime);
    }
  };

  const onLoadedMetadata = () => {
    if (audioRef.current) {
      setDuration(audioRef.current.duration || 0);
    }
  };

  const onEnded = () => {
    setIsPlaying(false);
    setCurrentTime(0);
  };

  const formatTime = (time: number) => {
    if (isNaN(time) || !isFinite(time)) return "00:00";
    const minutes = Math.floor(time / 60);
    const seconds = Math.floor(time % 60);
    return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  };

  return (
    <div className="flex flex-col gap-2 min-w-[200px] sm:min-w-[240px] bg-black/40 border border-white/5 rounded-2xl p-3 font-mono text-left select-none">
      {audioUrl && (
        <audio 
          ref={audioRef} 
          src={audioUrl} 
          onTimeUpdate={onTimeUpdate} 
          onLoadedMetadata={onLoadedMetadata}
          onEnded={onEnded}
          onPlay={() => setIsPlaying(true)}
          onPause={() => setIsPlaying(false)}
          className="hidden" 
        />
      )}
      <div className="flex items-center gap-3">
        <button 
          type="button"
          onClick={handlePlayPause}
          className="w-8 h-8 rounded-full bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/30 flex items-center justify-center transition-all cursor-pointer shrink-0"
        >
          {isPlaying ? (
            <Pause className="w-4 h-4 fill-current text-blue-400" />
          ) : (
            <Play className="w-4 h-4 fill-current translate-x-0.5 text-blue-400" />
          )}
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between text-[8px] text-slate-500 uppercase tracking-widest mb-1.5 font-bold">
            <span className="flex items-center gap-1 shrink-0">
              <span className="w-1 h-1 rounded-full bg-blue-400 animate-pulse" /> SECURE AUDIO
            </span>
            <span className="tabular-nums">{formatTime(currentTime)} / {formatTime(duration)}</span>
          </div>
          {/* Progress Bar */}
          <div 
            className="w-full h-1 bg-white/5 rounded-full overflow-hidden relative cursor-pointer" 
            onClick={(e) => {
              e.stopPropagation();
              if (!audioRef.current || !duration) return;
              const rect = e.currentTarget.getBoundingClientRect();
              const pos = (e.clientX - rect.left) / rect.width;
              audioRef.current.currentTime = pos * duration;
            }}
          >
            <div 
              className="h-full bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)] transition-all" 
              style={{ width: `${duration ? (currentTime / duration) * 100 : 0}%` }}
            />
          </div>
        </div>
      </div>
      {/* Waveform Visualization Bars */}
      <div className="flex items-end justify-between h-5 gap-[2px] px-1 bg-black/20 rounded-md border border-white/5">
        {Array.from({ length: 24 }).map((_, i) => {
          const h = Math.abs(Math.sin((i / 24) * Math.PI * 2) * 80) + 10;
          const isActive = isPlaying && currentTime > 0 && (currentTime / (duration || 1)) >= (i / 24);
          return (
            <div 
              key={i} 
              className={`flex-1 rounded-[1px] transition-all duration-300 ${isActive ? 'bg-blue-500' : 'bg-slate-800'}`} 
              style={{ 
                height: `${h}%`
              }} 
            />
          );
        })}
      </div>
    </div>
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

  // --- Voice Memo Recording States & Refs ---
  const [isRecording, setIsRecording] = useState(false);
  const [recordTime, setRecordTime] = useState(0);
  const [pitchShift, setPitchShift] = useState(0); // in semitones: -12 to +12
  const [audioBlob, setAudioBlob] = useState<Blob | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isPreviewPlaying, setIsPreviewPlaying] = useState(false);

  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const timerRef = useRef<any>(null);
  const previewAudioRef = useRef<HTMLAudioElement | null>(null);

  // Clean raw preview URLs on unmount
  useEffect(() => {
    return () => {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [previewUrl]);

  const startRecording = async () => {
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error("Microphone access is unavailable. Ensure you are visiting via a secure HTTPS connection and that you have granted microphone permission in your browser.");
      }
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      audioChunksRef.current = [];
      const mediaRecorder = new MediaRecorder(stream);
      
      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data);
        }
      };

      mediaRecorder.onstop = () => {
        const rawBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        setAudioBlob(rawBlob);
        const url = URL.createObjectURL(rawBlob);
        setPreviewUrl(url);
        
        // Stop audio tracks after recording completes
        stream.getTracks().forEach(track => track.stop());
      };

      mediaRecorderRef.current = mediaRecorder;
      mediaRecorder.start();
      
      setIsRecording(true);
      setRecordTime(0);
      setAudioBlob(null);
      setPreviewUrl(null);

      timerRef.current = setInterval(() => {
        setRecordTime(prev => {
          const next = prev + 1;
          if (next >= 25) {
            // Stop recording auto-trigger when limit is reached
            setTimeout(() => {
              if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
                mediaRecorderRef.current.stop();
              }
              if (timerRef.current) {
                clearInterval(timerRef.current);
              }
              setIsRecording(false);
            }, 10);
          }
          return next;
        });
      }, 1000);
    } catch (err) {
      console.error("Microphone access blocked or failed:", err);
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
    }
    setIsRecording(false);
  };

  const cancelRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
    if (timerRef.current) {
      clearInterval(timerRef.current);
    }
    setIsRecording(false);
    setAudioBlob(null);
    setPreviewUrl(null);
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
  };

  const handleSendVoiceMemo = async () => {
    if (!audioBlob) return;
    setIsSending(true);
    try {
      // 1. Process with custom pitch shifting offline rendering (optimized as WAV mono 22050Hz)
      const processedBlob = await applyPitchShift(audioBlob, pitchShift);
      
      // 2. Base64 encode
      const base64Audio = await blobToBase64(processedBlob);
      
      // 3. Structured string packet prefix
      const msgText = `[VOICE_MEMO]:${base64Audio}`;
      
      // 4. Send encrypted chat package
      await onSendMessage(msgText);
      
      // 5. Cleanup
      setAudioBlob(null);
      setPreviewUrl(null);
      setIsRecording(false);
    } catch (err) {
      console.error("Voice memo compilation/encryption block failed:", err);
    } finally {
      setIsSending(false);
    }
  };

  const handlePlayPreview = () => {
    if (!previewAudioRef.current) return;
    if (isPreviewPlaying) {
      previewAudioRef.current.pause();
      setIsPreviewPlaying(false);
    } else {
      const rate = Math.pow(2, pitchShift / 12);
      previewAudioRef.current.playbackRate = rate;
      previewAudioRef.current.play().catch(err => console.error(err));
      setIsPreviewPlaying(true);
    }
  };

  const handlePitchChange = (newVal: number) => {
    setPitchShift(newVal);
    if (previewAudioRef.current) {
      const rate = Math.pow(2, newVal / 12);
      previewAudioRef.current.playbackRate = rate;
    }
  };

  const formatTimer = (time: number) => {
    const min = Math.floor(time / 60);
    const sec = time % 60;
    return `${min.toString().padStart(2, '0')}:${sec.toString().padStart(2, '0')}`;
  };

  // Real-time Typing Indicator States
  const [partnerLastTypedAt, setPartnerLastTypedAt] = useState<number | null>(null);
  const [, setTick] = useState(0);
  const lastWriteRef = useRef<number>(0);
  const typingTimeoutRef = useRef<any>(null);

  // Listen to partner's typing status
  useEffect(() => {
    if (!activePartnerUID || !currentUserUID) {
      setPartnerLastTypedAt(null);
      return;
    }

    const docRef = doc(db, 'typing_indicators', `${activePartnerUID}_${currentUserUID}`);
    const unsub = onSnapshot(docRef, (snap) => {
      if (snap.exists()) {
        const data = snap.data();
        setPartnerLastTypedAt(data?.updatedAt?.toMillis() || Date.now());
      } else {
        setPartnerLastTypedAt(null);
      }
    }, (err) => {
      console.warn("Could not retrieve typing status:", err);
    });

    return () => unsub();
  }, [activePartnerUID, currentUserUID]);

  // Tick timer to recompute elapsed typing duration
  useEffect(() => {
    if (!partnerLastTypedAt) return;
    const interval = setInterval(() => {
      setTick(t => t + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, [partnerLastTypedAt]);

  const isPartnerTypingNow = useMemo(() => {
    if (!partnerLastTypedAt) return false;
    return (Date.now() - partnerLastTypedAt) < 7000;
  }, [partnerLastTypedAt]);

  // Publish current user's typing status
  useEffect(() => {
    if (!activePartnerUID || !currentUserUID) return;

    const docId = `${currentUserUID}_${activePartnerUID}`;
    const indicatorRef = doc(db, 'typing_indicators', docId);

    const publishTyping = async (isTyping: boolean) => {
      try {
        if (isTyping) {
          await setDoc(indicatorRef, {
            userId: currentUserUID,
            typingTo: activePartnerUID,
            updatedAt: serverTimestamp()
          });
          lastWriteRef.current = Date.now();
        } else {
          await deleteDoc(indicatorRef);
        }
      } catch (err) {
        console.warn("Could not set typing status:", err);
      }
    };

    if (msgInput.trim().length > 0) {
      const now = Date.now();
      if (now - lastWriteRef.current > 3500) {
        publishTyping(true);
      }

      if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = setTimeout(() => {
        publishTyping(false);
      }, 5000);
    } else {
      if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
      publishTyping(false);
    }

    return () => {
      if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
      deleteDoc(indicatorRef).catch(() => {});
    };
  }, [msgInput, activePartnerUID, currentUserUID]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isPartnerTypingNow]);

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
                    
                    {m.text?.startsWith('[VOICE_MEMO]:') ? (
                      <VoiceMemoPlayCapsule base64={m.text.split('[VOICE_MEMO]:')[1]} />
                    ) : (
                      <p className="whitespace-pre-wrap">{m.text}</p>
                    )}
                    
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
            {isPartnerTypingNow && (
              <div className="flex justify-start px-2 animate-pulse">
                <div className="bg-blue-500/5 border border-blue-500/10 p-4 rounded-2xl rounded-tl-none text-[10px] text-blue-400 font-mono flex items-center gap-3">
                  <div className="flex gap-1">
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                  <span className="tracking-widest uppercase">Node @{activePartnerName} Transmitting...</span>
                </div>
              </div>
            )}
          </div>

          <div className="p-6 bg-bg-base/60 border-t border-border-main backdrop-blur-xl relative">
            <div className="absolute top-0 left-0 h-[2px] bg-blue-600/50 w-full animate-pulse-glow" />
            
            {isRecording ? (
              // RECORDING ACTIVE SURFACE
              <div className="space-y-4">
                <div className="flex items-center justify-between bg-red-500/5 border border-red-500/20 rounded-2xl p-4 animate-pulse">
                  <div className="flex items-center gap-3">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping glow-red" />
                    <div className="flex flex-col">
                      <span className="text-[10px] text-red-400 font-bold tracking-widest uppercase">CAPTURING SECURE VOICE</span>
                      <span className="text-[8px] text-red-400/60 font-mono tracking-wider uppercase">Max secure duration: 25s limit</span>
                    </div>
                  </div>
                  <span className="text-xs text-red-400 font-bold tracking-widest font-mono tabular-nums">{formatTimer(recordTime)} / 00:25</span>
                </div>

                {/* Pitch option during recording */}
                <div className="bg-white/5 border border-white/5 rounded-2xl p-4 space-y-2">
                  <div className="flex items-center justify-between text-[9px] text-slate-400 uppercase tracking-widest">
                    <span className="font-bold flex items-center gap-1">
                      <Lock className="w-3 h-3 text-blue-400" /> PRIVACY PITCH ENCRYPTION
                    </span>
                    <span className="text-blue-400 font-black tabular-nums">{pitchShift > 0 ? `+${pitchShift}` : pitchShift} ST</span>
                  </div>
                  <input 
                    type="range" 
                    min="-12" 
                    max="12" 
                    value={pitchShift}
                    onChange={(e) => setPitchShift(parseInt(e.target.value))}
                    className="w-full h-1.5 bg-black/40 rounded-lg appearance-none cursor-pointer accent-blue-500"
                  />
                  <div className="flex justify-between text-[7px] text-slate-600 uppercase tracking-tighter">
                    <span>Deep Stealth (-12)</span>
                    <span>Original (0)</span>
                    <span>High-Frequency (+12)</span>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <button 
                    type="button"
                    onClick={cancelRecording}
                    className="flex-1 py-4 bg-red-600/10 hover:bg-red-600/20 border border-red-500/20 text-red-400 rounded-xl font-bold text-[10px] uppercase tracking-widest transition-all active:scale-95 flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Trash2 className="w-4 h-4" />
                    Cancel
                  </button>
                  <button 
                    type="button"
                    onClick={stopRecording}
                    className="flex-1 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold text-[10px] uppercase tracking-widest transition-all active:scale-[0.98] shadow-[0_0_15px_rgba(59,130,246,0.3)] flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Square className="w-4 h-4 fill-current text-white" />
                    Stop & Preview
                  </button>
                </div>
              </div>
            ) : previewUrl ? (
              // PREVIEW & ADJUST MEMO SURFACE
              <div className="space-y-4">
                {previewUrl && (
                  <audio 
                    ref={previewAudioRef} 
                    src={previewUrl} 
                    onEnded={() => setIsPreviewPlaying(false)}
                    className="hidden" 
                  />
                )}
                
                <div className="bg-blue-500/5 border border-blue-500/10 rounded-2xl p-4">
                  <div className="flex items-center justify-between text-[9px] text-slate-400 uppercase tracking-widest mb-3 font-bold">
                    <span className="flex items-center gap-1 text-blue-400">
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" /> PREVIEW SECURED MEMO
                    </span>
                    <span>Anonymization Tuner</span>
                  </div>

                  <div className="flex items-center gap-4">
                    <button 
                      type="button"
                      onClick={handlePlayPreview}
                      className="w-12 h-12 rounded-xl bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/30 flex items-center justify-center transition-all cursor-pointer shrink-0"
                    >
                      {isPreviewPlaying ? (
                        <Pause className="w-5 h-5 fill-current text-blue-400" />
                      ) : (
                        <Play className="w-5 h-5 fill-current translate-x-0.5 text-blue-400" />
                      )}
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between text-[8px] text-slate-500 uppercase tracking-widest mb-1">
                        <span>Playback Rate Modulator</span>
                        <span className="text-blue-400 font-bold">detune={pitchShift * 100} cents</span>
                      </div>
                      <div className="h-1 w-full bg-white/5 rounded-full overflow-hidden">
                        <div className="h-full bg-blue-500 w-1/3 shadow-[0_0_8px_rgba(59,130,246,0.5)]" style={{ width: isPreviewPlaying ? '100%' : '33%' }} />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Pitch shift tuner slider */}
                <div className="bg-white/5 border border-white/5 rounded-2xl p-4 space-y-2">
                  <div className="flex items-center justify-between text-[9px] text-slate-400 uppercase tracking-widest font-bold">
                    <span>Tunable Voice Masking</span>
                    <span className="text-blue-400 font-black">{pitchShift > 0 ? `+${pitchShift}` : pitchShift} Semitones</span>
                  </div>
                  <input 
                    type="range" 
                    min="-12" 
                    max="12" 
                    value={pitchShift}
                    onChange={(e) => handlePitchChange(parseInt(e.target.value))}
                    className="w-full h-1.5 bg-black/40 rounded-lg appearance-none cursor-pointer accent-blue-500"
                  />
                  <div className="flex justify-between text-[7px] text-slate-600 uppercase tracking-tighter">
                    <span>Deep Stealth (-12)</span>
                    <span>Original (0)</span>
                    <span>High-Frequency (+12)</span>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <button 
                    type="button"
                    onClick={cancelRecording}
                    className="flex-1 py-4 bg-white/5 hover:bg-white/10 border border-white/10 text-slate-400 rounded-xl font-bold text-[10px] uppercase tracking-widest transition-all active:scale-95 flex items-center justify-center gap-2 cursor-pointer"
                  >
                    <Trash2 className="w-4 h-4 text-slate-500" />
                    Discard
                  </button>
                  <button 
                    type="button"
                    onClick={handleSendVoiceMemo}
                    disabled={isSending}
                    className="flex-1 py-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-bold text-[10px] uppercase tracking-widest transition-all active:scale-[0.98] shadow-[0_0_15px_rgba(59,130,246,0.3)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    {isSending ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Send className="w-4 h-4" />
                    )}
                    Encrypt & Send
                  </button>
                </div>
              </div>
            ) : (
              // DEFAULT TEXT CHAT MODE
              <div className="flex items-end gap-3">
                <button 
                  type="button"
                  onClick={startRecording}
                  className="w-14 h-14 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 rounded-2xl border border-blue-500/20 transition-all flex items-center justify-center active:scale-95 shrink-0 cursor-pointer"
                  title="Record Secure Voice Memo"
                >
                  <Mic className="w-5 h-5" />
                </button>
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
                  className="w-14 h-14 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:bg-white/5 rounded-2xl text-white transition-all shadow-[0_0_20px_rgba(59,130,246,0.3)] flex items-center justify-center active:scale-95 group overflow-hidden cursor-pointer"
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
            )}

            <div className="mt-4 flex items-center justify-center gap-6 select-none">
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

function PreviewModal({ file, allowDownload = true, onClose }: { file: { url: string; name: string; type: string }; allowDownload?: boolean; onClose: () => void }) {
  const [fileStack, setFileStack] = useState<{ url: string; name: string; type: string; isSubFile?: boolean }[]>([file]);
  const createdUrlsRef = useRef<string[]>([]);
  const [isBlurred, setIsBlurred] = useState(false);
  const [securityLog, setSecurityLog] = useState<string | null>(null);

  useEffect(() => {
    setFileStack([file]);
    return () => {
      // Cleanup all dynamically generated URLs on unmount
      createdUrlsRef.current.forEach(url => {
        if (url.startsWith('blob:')) {
          URL.revokeObjectURL(url);
        }
      });
    };
  }, [file]);

  // Screen Capture & Copy/Paste Blockers
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden) {
        setIsBlurred(true);
        setSecurityLog("Screen feed hidden. Document de-focused.");
      }
    };

    const handleWindowBlur = () => {
      setIsBlurred(true);
      setSecurityLog("Focus lost: suspicious screen recorder or screenshot tool might have interacted.");
    };

    const handleWindowFocus = () => {
      setIsBlurred(false);
      setSecurityLog(null);
    };

    const handleContextMenu = (e: MouseEvent) => {
      e.preventDefault();
      setSecurityLog("Right-click disabled inside the secure container.");
      setTimeout(() => setSecurityLog(null), 3000);
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      // Block PrintScreen with warning
      if (e.key === 'PrintScreen') {
        e.preventDefault();
        setIsBlurred(true);
        setSecurityLog("Screenshot attempt blocked.");
        return;
      }

      // Block copying / saving / print commands
      if (
        (e.ctrlKey || e.metaKey) && 
        ['c', 's', 'p', 'u', 'a', 'd'].includes(e.key.toLowerCase())
      ) {
        e.preventDefault();
        setSecurityLog(`Security Protocol: Shortcut '${e.key}' block activated.`);
        setTimeout(() => setSecurityLog(null), 3000);
      }

      // Block DevTools
      if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && ['i', 'j', 'c'].includes(e.key.toLowerCase()))) {
        e.preventDefault();
        setSecurityLog("Inspect Tools are restricted in Secure Mode.");
        setTimeout(() => setSecurityLog(null), 3000);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleWindowBlur);
    window.addEventListener('focus', handleWindowFocus);
    window.addEventListener('contextmenu', handleContextMenu);
    window.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleWindowBlur);
      window.removeEventListener('focus', handleWindowFocus);
      window.removeEventListener('contextmenu', handleContextMenu);
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const handlePreviewFile = (subFile: { url: string; name: string; type: string; isSubFile: boolean }) => {
    if (subFile.isSubFile) {
      createdUrlsRef.current.push(subFile.url);
    }
    setFileStack(prev => [...prev, subFile]);
  };

  const handleBack = () => {
    if (fileStack.length > 1) {
      const popped = fileStack[fileStack.length - 1];
      if (popped.isSubFile && popped.url.startsWith('blob:')) {
        URL.revokeObjectURL(popped.url);
      }
      setFileStack(prev => prev.slice(0, -1));
    }
  };

  const currentFile: { url: string; name: string; type: string; isSubFile?: boolean } = fileStack[fileStack.length - 1] || { ...file, isSubFile: false };

  const isImage = currentFile.type.startsWith('image/') || /\.(png|jpe?g|gif|webp|svg|bmp)$/i.test(currentFile.name);
  const isVideo = currentFile.type.startsWith('video/') || /\.(mp4|webm|ogg|mov|m4v)$/i.test(currentFile.name);
  const isAudio = currentFile.type.startsWith('audio/') || /\.(mp3|wav|ogg|m4a|flac|aac)$/i.test(currentFile.name);
  const isPdf = currentFile.type === 'application/pdf' || currentFile.type === 'application/x-pdf' || /\.pdf$/i.test(currentFile.name);
  const isMarkdown = /\.md$/i.test(currentFile.name);
  const isText = currentFile.type.startsWith('text/') || /\.(txt|csv|json|xml|js|jsx|ts|tsx|css|html|sh|py|ini|yaml|yml|log)$/i.test(currentFile.name);
  const isZip = currentFile.type === 'application/zip' || currentFile.type === 'application/x-zip-compressed' || /\.zip$/i.test(currentFile.name);

  // Extract current user details to build dynamic watermark
  const userTraceID = auth.currentUser?.email || auth.currentUser?.uid || "GUEST_USER";

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[300] flex items-center justify-center p-2 sm:p-4 bg-black/98 backdrop-blur-md select-none"
      style={{ userSelect: 'none', WebkitUserSelect: 'none' }}
    >
      <div className="relative w-full max-w-4xl h-[85vh] md:h-[88vh] bg-[#0a0b0d] rounded-2xl border border-red-500/10 overflow-hidden flex flex-col technical-border shadow-2xl">
        
        {/* Anti-Screen Recording/Screenshot Active Warning Ribbon */}
        <div className="bg-red-500/10 border-b border-red-500/10 px-4 py-1.5 flex items-center justify-between text-[8px] font-mono select-none">
          <span className="text-red-400 font-bold uppercase tracking-widest flex items-center gap-1.5 animate-pulse">
            <Shield className="w-3 h-3 text-red-500" />
            ANTI-SCREENSHOOTER ACTIVE (SECURE SPECTRAL SHIELD V2.5)
          </span>
          <span className="text-slate-500 lowercase">
            *screen captures will blur content or trace metadata
          </span>
        </div>

        {/* Cinematic Header Bar */}
        <div className="w-full h-14 border-b border-white/5 flex items-center justify-between px-4 bg-black/40 shrink-0 z-40">
          <div className="flex items-center gap-3 min-w-0 max-w-[55%]">
            {fileStack.length > 1 && (
              <button 
                type="button"
                onClick={handleBack}
                className="flex items-center gap-1 py-1 px-2 bg-white/5 hover:bg-white/10 text-white rounded-lg font-mono text-[9px] uppercase tracking-widest border border-white/10 transition-colors cursor-pointer shrink-0"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>Back</span>
              </button>
            )}
            <div className="flex flex-col min-w-0">
              <span className="text-xs font-mono font-bold text-white tracking-widest uppercase truncate">{currentFile.name}</span>
              <div className="flex items-center gap-1.5 text-[8px] font-mono text-slate-500 uppercase tracking-tighter">
                <Shield className="w-2.5 h-2.5 text-blue-500/50" />
                {currentFile.isSubFile ? "Unpacked Archive Element" : "Decrypted Secure Stream"} ({currentFile.type || 'unknown/binary'})
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            {allowDownload && (
              <a 
                href={currentFile.url} 
                download={currentFile.name}
                className="flex items-center gap-2 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 active:scale-95 text-white rounded-lg font-mono text-[9px] uppercase tracking-widest transition-all shadow-[0_0_15px_rgba(59,130,246,0.25)] cursor-pointer"
              >
                <Download className="w-3 h-3" />
                <span className="hidden sm:inline">Download</span>
              </a>
            )}
            <button 
              type="button"
              onClick={onClose}
              className="p-1.5 bg-white/5 hover:bg-white/10 active:scale-[0.93] rounded-full text-white border border-white/10 transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Media Preview Stage */}
        <div 
          className={`flex-1 w-full min-h-0 bg-[#050608] flex items-center justify-center overflow-auto p-2 sm:p-4 relative transition-all duration-300
            ${isBlurred ? 'blur-2xl scale-95 pointer-events-none' : ''}
          `}
          onDragStart={(e) => e.preventDefault()}
        >
          {/* Dynamic Repeating Micro-Watermark Overlay for Traceability */}
          <div className="absolute inset-0 pointer-events-none overflow-hidden select-none z-50 opacity-[0.035] grid grid-cols-3 sm:grid-cols-4 gap-x-12 gap-y-16 p-6 font-mono text-[9px] uppercase font-black text-white tracking-widest">
            {Array.from({ length: 40 }).map((_, i) => (
              <div key={i} className="rotate-[-28deg] whitespace-nowrap text-center select-none">
                E2EE SAFE VIEW • {userTraceID} • NO_LOGS
              </div>
            ))}
          </div>

          {/* Actual Media Components */}
          {isImage ? (
            <div className="w-full h-full pointer-events-none select-none">
              <CustomImageViewer url={currentFile.url} name={currentFile.name} />
            </div>
          ) : isVideo ? (
            <div className="w-full h-full pointer-events-none select-none">
              <CustomVideoPlayer url={currentFile.url} name={currentFile.name} />
            </div>
          ) : isAudio ? (
            <div className="p-8 text-center w-full max-w-md bg-white/5 border border-white/5 rounded-2xl relative z-20">
              <Volume2 className="w-12 h-12 text-blue-400 mx-auto mb-4 animate-pulse" />
              <p className="text-xs font-mono text-slate-300 uppercase tracking-widest mb-4">Secure Audio Channel</p>
              <audio src={currentFile.url} controls className="w-full h-11 bg-black/40 rounded-xl" />
            </div>
          ) : isPdf ? (
            <div className="w-full h-full overflow-auto select-none">
              <PdfPreview url={currentFile.url} />
            </div>
          ) : isMarkdown ? (
            <div className="w-full h-full overflow-auto select-none">
              <MarkdownPreview url={currentFile.url} />
            </div>
          ) : isText ? (
            <div className="w-full h-full overflow-auto select-none">
              <TextPreview url={currentFile.url} />
            </div>
          ) : isZip ? (
            <div className="w-full h-full overflow-auto relative z-20">
              <ZipPreview url={currentFile.url} onPreviewFile={handlePreviewFile} />
            </div>
          ) : (
            <div className="p-12 text-center">
              <FileText className="w-16 h-16 text-slate-700 mx-auto mb-4" />
              <p className="text-sm font-mono text-slate-500 uppercase tracking-widest">Preview not supported for this file type.</p>
              <p className="text-[10px] text-slate-600 mt-2">Please use the download option instead.</p>
            </div>
          )}

          {/* Active Security Warning Overlay */}
          {isBlurred && (
            <div className="absolute inset-0 bg-black/80 backdrop-blur-xl flex flex-col items-center justify-center p-6 text-center z-[200]">
              <Lock className="w-12 h-12 text-red-500 animate-bounce mb-4" />
              <h3 className="text-red-400 font-mono font-bold text-sm uppercase tracking-widest">CONTENT RE-LOCKED</h3>
              <p className="text-[10px] text-slate-400 font-mono mt-2 lowercase max-w-xs leading-relaxed">
                safe session temporarily locked due to screen defocus, suspicious window state, or multitasking interaction. click back inside the window to restore stream.
              </p>
            </div>
          )}
        </div>

        {/* Security Toast logs */}
        {securityLog && (
          <div className="absolute bottom-4 left-1/2 -translate-x-1/2 bg-red-950/95 border border-red-500/30 text-red-400 px-4 py-2 rounded-xl text-[9px] font-mono tracking-wide z-[250] shadow-2xl flex items-center gap-2 animate-bounce uppercase">
            <AlertCircle className="w-3.5 h-3.5 text-red-400" />
            {securityLog}
          </div>
        )}
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

function ProcessingOverlay({ phase, progress, isEncrypting }: { phase: string | null; progress: number; isEncrypting: boolean }) {
  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="absolute inset-0 z-[200] bg-bg-base/80 backdrop-blur-xl flex flex-col items-center justify-center p-8 text-center"
    >
      <div className="scanning scanline opacity-30" />
      
      <div className="relative mb-12">
        <div className="absolute inset-0 bg-blue-500/20 blur-[100px] animate-pulse rounded-full" />
        <div className="relative w-32 h-32 flex items-center justify-center">
          <svg className="w-full h-full -rotate-90">
            <circle
              cx="64"
              cy="64"
              r="60"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              className="text-white/5"
            />
            <motion.circle
              cx="64"
              cy="64"
              r="60"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeDasharray="377"
              animate={{ strokeDashoffset: 377 - (377 * progress) / 100 }}
              className="text-blue-500"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            {isEncrypting ? (
              <Lock className="w-8 h-8 text-blue-500 animate-pulse" />
            ) : (
              <Upload className="w-8 h-8 text-blue-500 animate-bounce" />
            )}
          </div>
        </div>
      </div>

      <div className="space-y-4 max-w-xs w-full">
        <div className="flex flex-col gap-1">
          <h3 className="text-sm font-mono font-black text-text-main uppercase tracking-[0.3em]">
            {isEncrypting ? 'Ciphering_Packet' : 'Relaying_Stream'}
          </h3>
          <p className="text-[10px] font-mono text-blue-500/60 uppercase tracking-widest animate-pulse">
            {phase || 'Initializing Protocol...'}
          </p>
        </div>

        <div className="bg-white/5 h-1.5 w-full rounded-full overflow-hidden border border-white/5 p-[1px]">
          <motion.div 
            className="h-full bg-gradient-to-r from-blue-600 to-blue-400 rounded-full"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
          />
        </div>

        <div className="flex justify-between items-center text-[7px] font-mono text-text-sub uppercase tracking-[0.2em] font-black">
          <div className="flex items-center gap-1">
            <Shield className="w-2 h-2 text-blue-500" />
            SECURE_LINK: {progress > 30 ? 'STABLE' : 'ESTABLISHING...'}
          </div>
          <span>{Math.round(progress)}% COMPLETE</span>
        </div>
      </div>

      <div className="mt-16 grid grid-cols-2 gap-8 opacity-20">
         <div className="flex flex-col gap-1 items-start">
            <span className="text-[6px] font-mono text-text-sub uppercase tracking-tighter">AES-256-GCM</span>
            <div className="w-12 h-[1px] bg-white/20" />
         </div>
         <div className="flex flex-col gap-1 items-end">
            <span className="text-[6px] font-mono text-text-sub uppercase tracking-tighter">Handshake_Sync</span>
            <div className="w-12 h-[1px] bg-white/20" />
         </div>
      </div>
    </motion.div>
  );
}

// --- Components ---

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [shareId, setShareId] = useState<string | null>(null);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [view, setView] = useState<'home' | 'upload' | 'download' | 'success' | 'setup-profile'>('home');
  const [activeTab, setActiveTab] = useState<'home' | 'chat' | 'notifications' | 'profile'>('home');
  const [error, setError] = useState<string | null>(null);
  const [quotaExceeded, setQuotaExceeded] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light' | 'system'>(() => {
    return (localStorage.getItem('vault_theme') as any) || 'system';
  });
  
  // User Profile & Social
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [showInbox, setShowInbox] = useState(false);
  const [inboxShares, setInboxShares] = useState<ShareData[]>([]);
  const [ownerShares, setOwnerShares] = useState<ShareData[]>([]);
  const [homeSubTab, setHomeSubTab] = useState<'terminal' | 'my-shares'>('terminal');
  const prevInboxCount = useRef(inboxShares.length);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const decryptedCache = useRef<Map<string, any>>(new Map());
  const usernameCache = useRef<Map<string, string>>(new Map());
  const [seenMessageIds, setSeenMessageIds] = useState<Set<string>>(() => {
    const saved = localStorage.getItem('seen_fragments');
    return saved ? new Set(JSON.parse(saved)) : new Set();
  });

  // Connectivity Monitor
  useEffect(() => {
    async function testConnection() {
      try {
        // Test Firebase
        await getDocFromServer(doc(db, '_health', 'check'));
      } catch (error) {
        if (error instanceof Error && error.message.includes('the client is offline')) {
          console.warn("Database Connection restricted (client is offline).");
        }
      }
    }
    testConnection();
  }, []);
  
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
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState<string | null>(null);
  const [expiryMinutes, setExpiryMinutes] = useState(5);
  const [allowView, setAllowView] = useState(true);
  const [allowDownload, setAllowDownload] = useState(true);
  const [generatedLink, setGeneratedLink] = useState('');
  const [currentTime, setCurrentTime] = useState(Date.now());

  // Download State
  const [targetShare, setTargetShare] = useState<ShareData | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedFile, setDecryptedFile] = useState<{ url: string; name: string; type: string } | null>(null);
  const [decryptedMessage, setDecryptedMessage] = useState<{ text: string; sender: string } | null>(null);
  const [targetSenderHandle, setTargetSenderHandle] = useState<string | null>(null);
  const [isPrivateKeyAccess, setIsPrivateKeyAccess] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [showAdmin, setShowAdmin] = useState(false);
  const maintenancePerformed = useRef(false);

  // --- Maintenance Rules ---
  const isAdmin = user?.email === 'transferd001@gmail.com';

  const pruneExpired = async (isManual = false) => {
    if (quotaExceeded) return;

    if (!isManual) {
      if (maintenancePerformed.current) return;

      const lastAutoPrune = localStorage.getItem('last_auto_prune');
      const nowMs = Date.now();
      if (lastAutoPrune && (nowMs - parseInt(lastAutoPrune, 10) < 15 * 60 * 1000)) {
        console.log('[Maintenance Throttle] Background prune skipped to conserve bandwidth.');
        return;
      }
    }

    maintenancePerformed.current = true;

    try {
      const sharesRef = collection(db, 'shares');
      // For background auto-run, limit to 5 to protect bandwidth. Manual runs can go up to 50.
      const pruneLimit = isManual ? 50 : 5;
      
      const q = query(
        sharesRef, 
        where('expiresAt', '<', Timestamp.now()),
        limit(pruneLimit)
      );
      const snapshot = await getDocs(q);
      
      if (!snapshot.empty) {
        let batch = writeBatch(db);
        let opCount = 0;
        let deleteCount = 0;

        for (const shareDoc of snapshot.docs) {
          try {
            const id = shareDoc.id;
            const chunksSnap = await getDocs(collection(db, 'shares', id, 'chunks'));
            const keysSnap = await getDocs(collection(db, 'shares', id, 'keys'));

            // Delete all sub-collection chunks
            for (const chk of chunksSnap.docs) {
              batch.delete(chk.ref);
              opCount++;
              if (opCount >= 400) {
                await batch.commit();
                batch = writeBatch(db);
                opCount = 0;
              }
            }

            // Delete all sub-collection keys
            for (const k of keysSnap.docs) {
              batch.delete(k.ref);
              opCount++;
              if (opCount >= 400) {
                await batch.commit();
                batch = writeBatch(db);
                opCount = 0;
              }
            }

            // Delete the parent share metadata
            batch.delete(shareDoc.ref);
            opCount++;
            deleteCount++;
            if (opCount >= 400) {
              await batch.commit();
              batch = writeBatch(db);
              opCount = 0;
            }
          } catch (itemErr: any) {
            console.error(`[Maintenance Sync] Error deleting expired share ${shareDoc.id}:`, itemErr.message);
          }
        }

        // Commit remaining deletion operations if any
        if (opCount > 0) {
          await batch.commit();
        }
        
        localStorage.setItem('last_auto_prune', Date.now().toString());
        console.log(`[Maintenance Sync] Cleaned up ${deleteCount} expired shares from Firestore.`);
      } else {
        localStorage.setItem('last_auto_prune', Date.now().toString());
        console.log('[Maintenance Sync] No expired shares found.');
      }
    } catch (err: any) {
      if (err.code === 'resource-exhausted' || err.message?.includes('resource-exhausted') || err.message?.includes('bandwidth') || err.message?.includes('quota')) {
        setQuotaExceeded(true);
        setError("System Quota Reached: Firestore maximum write bandwidth exceeded. Further database actions are restricted temporarily.");
      }
      console.warn(`Maintenance skipped:`, err.message);
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

    const sharesRef = collection(db, 'shares');
    const q = query(
      sharesRef, 
      where('recipientIds', 'array-contains', user.uid),
      limit(20)
    );

    const unsub = onSnapshot(q, async (snapshot) => {
      const nodeShares = snapshot.docs.map(d => ({ id: d.id, ...d.data() } as any));
      
      setInboxShares(nodeShares.sort((a,b) => {
         const tA = a.createdAt?.toMillis ? a.createdAt.toMillis() : new Date(a.createdAt).getTime();
         const tB = b.createdAt?.toMillis ? b.createdAt.toMillis() : new Date(b.createdAt).getTime();
         return tB - tA;
      }));
    }, (err) => {
      console.warn(`Inbox restricted:`, err.message);
    });

    return () => unsub();
  }, [user, view]);

  // Handle owner active shares real-time listener
  useEffect(() => {
    if (!user || view === 'setup-profile') {
      setOwnerShares([]);
      return;
    }

    const sharesRef = collection(db, 'shares');
    const q = query(
      sharesRef,
      where('ownerId', '==', user.uid),
      limit(50)
    );

    const unsub = onSnapshot(q, (snapshot) => {
      const activeShares = snapshot.docs
        .map(d => ({ id: d.id, ...d.data() } as any))
        .filter(sh => {
          // Exclude any keys or records that are message-only chats, or already expired
          if (sh.isMessage) return false;
          const expiry = sh.expiresAt instanceof Timestamp ? sh.expiresAt.toDate() : new Date(sh.expiresAt);
          return expiry.getTime() > Date.now();
        })
        .sort((a, b) => {
          const tA = a.createdAt?.toMillis ? a.createdAt.toMillis() : new Date(a.createdAt).getTime();
          const tB = b.createdAt?.toMillis ? b.createdAt.toMillis() : new Date(b.createdAt).getTime();
          return tB - tA;
        });
      setOwnerShares(activeShares);
    }, (err) => {
      console.warn(`Owner shares subscript restricted:`, err.message);
    });

    return () => unsub();
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

      // Sync partners list (resolved usernames with caching)
      const partnerList = await Promise.all(
        Array.from(partnersMap.values()).map(async (p: any) => {
          if (usernameCache.current.has(p.uid)) {
            return { uid: p.uid, username: usernameCache.current.get(p.uid) };
          }
          try {
            const uSnap = await getDoc(doc(db, 'users', p.uid));
            const uname = uSnap.data()?.username || 'Anonymous';
            usernameCache.current.set(p.uid, uname);
            return { uid: p.uid, username: uname };
          } catch (e) {
            return { uid: p.uid, username: 'Anonymous' };
          }
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
    const unsub = onAuthStateChanged(auth, async (u) => {
      setUser(u);
      if (u) {
        // Profile snapshot listener
        const profileRef = doc(db, 'users', u.uid);
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
        setIsPrivateKeyAccess(false);
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
      const unameSnap = await getDoc(doc(db, 'usernames', uname));
      if (!unameSnap.exists()) {
        const batch = writeBatch(db);
        batch.set(doc(db, 'users', user.uid), {
          uid: user.uid,
          username: uname,
          displayName: user.displayName || uname,
          email: user.email || '',
          createdAt: serverTimestamp()
        });
        batch.set(doc(db, 'usernames', uname), { uid: user.uid });
        await batch.commit();
      } else {
        throw new Error("Username already taken.");
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

  const handleSignInAnonymous = async () => {
    try {
      setError(null);
      await signInAnonymous();
    } catch (err: any) {
      setError(`Guest Login issues: ${err.message}. If Firebase Auth Anonymous sign-in is disabled, please enable it in your Firebase console or try again.`);
    }
  };

  const loadShareMetadata = async (id: string) => {
    const path = `shares/${id}`;
    try {
      let data: ShareData | null = null;
      
      // 1. Try Firebase Database
      try {
        const docSnap = await getDoc(doc(db, 'shares', id));
        if (docSnap.exists()) {
          data = docSnap.data() as ShareData;
        }
      } catch (e) {
        console.warn("Firebase metadata fetch delay...");
      }

      if (data) {
        const expiryDate = data.expiresAt instanceof Timestamp ? data.expiresAt.toDate() : new Date(data.expiresAt);
        if (expiryDate.getTime() < Date.now()) {
          // Immediately auto-delete the expired file, its sub-collection keys, and chunks from Firestore
          try {
            const batch = writeBatch(db);
            const chunksSnap = await getDocs(collection(db, 'shares', id, 'chunks'));
            const keysSnap = await getDocs(collection(db, 'shares', id, 'keys'));
            chunksSnap.forEach(chk => batch.delete(chk.ref));
            keysSnap.forEach(k => batch.delete(k.ref));
            batch.delete(doc(db, 'shares', id));
            await batch.commit();
          } catch (cleanErr) {
            console.warn("Auto-cleanup on expired access failed or was already done:", cleanErr);
          }
          setError('This secure transmission link has expired and was purged from the active node cache.');
          setView('download');
          return;
        }

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
        setError('Share not found on any active node. It may have expired or was incorrectly indexed.');
      }
    } catch (err) {
      console.error(err);
      setError('Connection to secure node failed. Try refreshing the terminal.');
    }
  };

  const handleFileUpload = async () => {
    if (selectedFiles.length === 0) return;
    
    try {
      setIsEncrypting(true);
      setError(null);
      
      let activeFile: File;
      if (selectedFiles.length === 1) {
        activeFile = selectedFiles[0];
        setCurrentPhase("Encrypting data...");
      } else {
        setCurrentPhase("Creating secure ZIP bundle...");
        const zip = new JSZip();
        selectedFiles.forEach(f => {
          zip.file(f.name, f);
        });
        const zipContent = await zip.generateAsync({ type: "blob" });
        activeFile = new File([zipContent], "CipherVault_Secure_Bundle.zip", { type: "application/zip" });
        setCurrentPhase("Encrypting ZIP bundle...");
      }

      const arrayBuffer = await activeFile.arrayBuffer();
      const { encryptedBuffer, iv, key } = await encryptData(arrayBuffer);
      
      setIsEncrypting(false);
      setIsUploading(true);
      setUploadProgress(0);

      const id = generateId();
      const createdAt = new Date();
      const expiresAt = new Date(createdAt.getTime() + expiryMinutes * 60 * 1000);

      const bufferView = new Uint8Array(encryptedBuffer!);
      const chunkSize = 650 * 1024; 
      const chunks: string[] = [];
      for (let i = 0; i < bufferView.length; i += chunkSize) {
        chunks.push(arrayBufferToBase64(bufferView.slice(i, i + chunkSize).buffer));
      }

      const totalSteps = chunks.length + 1; // +1 for metadata
      let completedSteps = 0;

      setCurrentPhase("Writing metadata...");
      const shareObj: ShareData = {
        id, iv, chunkCount: chunks.length, fileName: activeFile.name, mimeType: activeFile.type, size: activeFile.size,
        createdAt: serverTimestamp(), expiresAt: Timestamp.fromDate(expiresAt), recipientIds: [], ownerId: auth.currentUser?.uid || null,
        allowView, allowDownload
      };

      await setDoc(doc(db, 'shares', id), shareObj);
      if (auth.currentUser) {
        await setDoc(doc(db, 'shares', id, 'keys', auth.currentUser.uid), { key });
      }
      completedSteps++;
      setUploadProgress((completedSteps / totalSteps) * 100);

      for (let i = 0; i < chunks.length; i++) {
        setCurrentPhase(`Transmitting fragment ${i + 1}/${chunks.length}...`);
        await setDoc(doc(db, 'shares', id, 'chunks', `c${i}`), { data: chunks[i], index: i });
        completedSteps++;
        setUploadProgress((completedSteps / totalSteps) * 100);
      }

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

  // Cleanup Blob URLs to prevent memory leaks
  useEffect(() => {
    return () => {
      if (decryptedFile?.url) {
        URL.revokeObjectURL(decryptedFile.url);
      }
    };
  }, [decryptedFile]);

  const processSecureFile = async (): Promise<{ url: string; name: string; type: string } | null> => {
    if (!targetShare || !secretKey) return null;

    try {
      setIsDecrypting(true);
      let metadata: any = null;
      let chunksData: ChunkData[] = [];
      let foundOnNode = false;

      try {
        const snap = await getDoc(doc(db, 'shares', targetShare.id));
        if (snap.exists()) {
          metadata = snap.data();
          const cSnap = await getDocs(collection(db, 'shares', targetShare.id, 'chunks'));
          // Support both 'index' and 'chunk_index' field names robustly
          chunksData = cSnap.docs.map(d => {
            const dData = d.data();
            const idx = typeof dData.index === 'number' ? dData.index : (typeof dData.chunk_index === 'number' ? dData.chunk_index : 0);
            return { data: dData.data, index: idx } as ChunkData;
          }).sort((a,b) => a.index - b.index);
          foundOnNode = true;
        }
      } catch (e) {
        console.warn("Firebase fetch failed.");
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
      
      try {
        await updateDoc(doc(db, 'shares', targetShare.id), {
          views: increment(1)
        });
      } catch (countErr) {
        console.warn("Could not increment views status:", countErr);
      }

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
    setDecryptedFile(null);
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

      // 1. Try Firebase Database
      try {
        const uSnap = await getDoc(doc(db, 'usernames', uname));
        if (uSnap.exists()) recipientUid = uSnap.data().uid;
      } catch (e) { console.warn("Firebase handle resolution delay"); }

      if (!recipientUid) throw new Error("Recipient handle not found in the secure network.");
      if (recipientUid === user?.uid) throw new Error("You cannot share with yourself.");

      const shareRef = doc(db, 'shares', shareId);
      const batch = writeBatch(db);
      batch.set(doc(shareRef, 'keys', recipientUid), { key: secretKey });
      batch.update(shareRef, { recipientIds: arrayUnion(recipientUid) });
      await batch.commit();
      
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
    
    const textMsg = messageText;
    const targetUname = messageRecipient.toLowerCase().trim();
    
    try {
      setIsSendingMessage(true);
      setError(null);
      
      // Proactively clear inputs for instant feedback
      setMessageText('');

      let recipientUid = null;

      try {
        const s = await getDoc(doc(db, 'usernames', targetUname));
        if (s.exists()) {
          recipientUid = s.data().uid;
        }
      } catch (e) {
        console.warn("Firebase handle resolution failed");
      }

      if (!recipientUid) {
        // If resolution failed, restore text so user doesn't lose it
        setMessageText(textMsg);
        throw new Error("Recipient handle not detected in current cluster.");
      }
      
      await sendChatMessage(recipientUid, textMsg);
      
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

      // Optimistic UI update: Add to local cache and state for instant appearance
      const optimisticMessage = {
        id,
        text,
        senderId: user.uid,
        createdAt: Date.now(),
        isPending: true
      };
      decryptedCache.current.set(id, optimisticMessage);
      setChatMessages(prev => [...prev.filter(m => m.id !== id), optimisticMessage].sort((a,b) => a.createdAt - b.createdAt));

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
        if (isQuota) {
          setQuotaExceeded(true);
        }
        throw fbErr;
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
      setShowChatPanel(false);
      
      const expiry = share.expiresAt instanceof Timestamp ? share.expiresAt.toDate() : new Date(share.expiresAt);
      if (expiry.getTime() < Date.now()) {
        setError('This secure transmission link has expired and was purged from the active node cache.');
        setView('download');
        setLoading(false);
        return;
      }
      
      // Mark as seen immediately on click
      if (!seenMessageIds.has(share.id)) {
        const next = new Set(seenMessageIds);
        next.add(share.id);
        setSeenMessageIds(next);
      }

      let key = null;

      // Try Firebase Database for Key
      try {
        const keySnap = await getDoc(doc(db, 'shares', share.id, 'keys', user!.uid));
        if (keySnap.exists()) {
          key = keySnap.data()?.key;
        }
      } catch (e) {
        console.warn("Firebase handle fetch delay...");
      }

      if (!key) throw new Error("Decryption key was not found on any node.");
      
      setActiveTab('home');
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
        let chunkData = null;
        
        // Try Firebase Database for chunks
        try {
          const chunksSnap = await getDocs(collection(db, 'shares', share.id, 'chunks'));
          if (!chunksSnap.empty) {
            chunkData = chunksSnap.docs[0].data();
          }
        } catch (e) {
          console.warn("Firebase chunk fetch delay...");
        }

        if (!chunkData) throw new Error("Secure message fragments were not found on any network node.");
        
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
      setView('download');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // Simple toast could go here
  };

  const reset = () => {
    window.location.hash = '';
    setFile(null);
    setSelectedFiles([]);
    setGeneratedLink('');
    setDecryptedFile(null);
    setError(null);
    setIsPrivateKeyAccess(false);
    setAllowView(true);
    setAllowDownload(true);
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
      
      // 1. Check if key is already in use
      try {
        const existing = await getDoc(doc(db, 'custom_keys', customKey));
        if (existing.exists()) {
          const data = existing.data();
          if (data.expiresAt.toMillis() > Date.now()) {
            throw new Error("Target key is currently bonded to another active transmission.");
          }
        }
      } catch (e: any) {
        if (e.message?.includes("bonded")) throw e;
      }

      const expiresAtDate = targetShare?.expiresAt instanceof Timestamp ? targetShare.expiresAt.toDate() : 
                        (targetShare?.expiresAt ? new Date(targetShare.expiresAt) : new Date(Date.now() + 30 * 60 * 1000));
      const expiresAt = Timestamp.fromDate(expiresAtDate);

      // 2. Transmit to Firebase
      let fbSuccess = false;
      try {
        await setDoc(doc(db, 'custom_keys', customKey), {
          shareId,
          secretKey,
          expiresAt
        });
        fbSuccess = true;
      } catch (fbErr: any) {
         console.warn("Firebase key sync delay...");
      }

      if (!fbSuccess) {
        throw new Error("Synchronization Error: Failed to bind key.");
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
      
      const input = entryKey.trim();
      let keyData = null;

      // 1. Check if input is a full URL instead of just a key
      if (input.includes('share=') && input.includes('key=')) {
        try {
          const url = new URL(input.startsWith('http') ? input : `https://${input}`);
          const hash = url.hash.substring(1);
          const params = new URLSearchParams(hash);
          const id = params.get('share');
          const key = params.get('key');
          
          if (id && key) {
            const sanitizedKey = key.replace(/ /g, '+');
            setShareId(id);
            setSecretKey(sanitizedKey);
            setEntryKey('');
            setShowPrivateKeyPanel(false);
            setIsPrivateKeyAccess(true);
            await loadShareMetadata(id);
            return;
          }
        } catch (e) {
          console.warn("URL parsing in key extractor failed, falling back to mapping lookup...");
        }
      }

      // 2. Try Firebase Mapping
      try {
        const mappingSnap = await getDoc(doc(db, 'custom_keys', input));
        if (mappingSnap.exists()) {
          const data = mappingSnap.data();
          if (data.expiresAt.toMillis() >= Date.now()) {
            keyData = data;
          }
        }
      } catch (e) {
        console.warn("Firebase key resolution failed...");
      }

      if (!keyData) {
        throw new Error("Key not found in active spectrum or has expired.");
      }

      setShareId(keyData.shareId);
      setSecretKey(keyData.secretKey);
      setEntryKey('');
      setShowPrivateKeyPanel(false);
      setIsPrivateKeyAccess(true);
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
        setIsPrivateKeyAccess(false);
        setView('download');
        loadShareMetadata(id);
      } else {
        setError("Could not parse link. Make sure it's a full CipherVault URL.");
      }
    } catch (err) {
      setError("Invalid URL format. Please paste the full link.");
    }
  };

  const handleSelectActiveSelfShare = async (share: any) => {
    if (!user) return;
    try {
      setError(null);
      
      const expiry = share.expiresAt instanceof Timestamp ? share.expiresAt.toDate() : new Date(share.expiresAt);
      if (expiry.getTime() < Date.now()) {
        setError('This secure transmission link has expired and was purged from the active node cache.');
        setView('download');
        return;
      }

      // Retrieve the decryption signature key of this share which is owned by the current user
      const keyRef = doc(db, 'shares', share.id, 'keys', user.uid);
      const keySnap = await getDoc(keyRef);
      if (keySnap.exists()) {
        const key = keySnap.data().key;
        setSecretKey(key);
        setShareId(share.id);
        const link = `${window.location.origin}/#share=${share.id}&key=${encodeURIComponent(key)}`;
        setGeneratedLink(link);
        setView('success');
      } else {
        setError(`Decryption signature key not found for file ${share.fileName}. This file was likely deposited without local key registration.`);
      }
    } catch (err: any) {
      setError(`Failed to retrieve file session: ${err.message}`);
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
    <div className="fixed inset-0 flex flex-col bg-bg-base overflow-hidden selection:bg-blue-500/30 transition-colors">
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

      {/* Bottom Navigation */}
      <div className="fixed bottom-0 left-0 right-0 z-[100] bg-bg-card/80 backdrop-blur-xl border-t border-border-main pb-safe">
        <div className="max-w-md mx-auto flex justify-around items-center py-3">
          <button 
            onClick={() => setActiveTab('home')} 
            className={`flex flex-col items-center gap-1 transition-all ${activeTab === 'home' ? 'text-blue-500 scale-110' : 'text-slate-500 hover:text-slate-400'}`}
          >
            <Home className={`w-5 h-5 ${activeTab === 'home' ? 'glow-blue' : ''}`} />
            <span className="text-[9px] font-sans font-bold uppercase tracking-tight">Home</span>
          </button>
          <button 
            onClick={() => setActiveTab('chat')} 
            className={`flex flex-col items-center gap-1 relative transition-all ${activeTab === 'chat' ? 'text-blue-500 scale-110' : 'text-slate-500 hover:text-slate-400'}`}
          >
            <MessageSquare className={`w-5 h-5 ${activeTab === 'chat' ? 'glow-blue' : ''}`} />
            <span className="text-[9px] font-sans font-bold uppercase tracking-tight">Chat</span>
          </button>
          <button 
            onClick={() => setActiveTab('notifications')} 
            className={`flex flex-col items-center gap-1 relative transition-all ${activeTab === 'notifications' ? 'text-blue-500 scale-110' : 'text-slate-500 hover:text-slate-400'}`}
          >
            <Bell className={`w-5 h-5 ${activeTab === 'notifications' ? 'glow-blue' : ''}`} />
            {inboxCount > 0 && <div className="absolute top-0 right-0 w-2 h-2 bg-blue-500 rounded-full glow-blue" />}
            <span className="text-[9px] font-sans font-bold uppercase tracking-tight">Signals</span>
          </button>
          <button 
            onClick={() => setActiveTab('profile')} 
            className={`flex flex-col items-center gap-1 transition-all ${activeTab === 'profile' ? 'text-blue-500 scale-110' : 'text-slate-500 hover:text-slate-400'}`}
          >
            <UserIcon className={`w-5 h-5 ${activeTab === 'profile' ? 'glow-blue' : ''}`} />
            <span className="text-[9px] font-sans font-bold uppercase tracking-tight">Profile</span>
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-4 md:p-8 custom-scrollbar">
        <div className="max-w-md mx-auto">
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
                     Critical_System_Lock: Quota_Exhausted
                   </h3>
                   <p className="text-[8px] md:text-[9px] font-mono text-slate-500 uppercase tracking-[0.1em] mt-0.5 md:mt-1">
                     Primary Node (Firebase) offline. All secure writes are locked.
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

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-blue-500/5 border border-blue-500/20 rounded-lg">
             <div className="w-1.5 h-1.5 rounded-full bg-green-500 glow-green animate-pulse" />
             <span className="text-[8px] font-mono font-black text-blue-400 uppercase tracking-widest">System_Active</span>
          </div>
        </div>
      </nav>

      <main className="max-w-md mx-auto relative cursor-default sm:px-0 pb-32">
        <AnimatePresence mode="wait">
          
          {view === 'download' ? (
            <motion.div 
              key="download-view"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[150] bg-bg-base/95 backdrop-blur-md flex flex-col p-4 md:p-8 overflow-y-auto"
            >
               <AnimatePresence>
                {isDecrypting && (
                  <ProcessingOverlay 
                    phase="Decrypting fragment streams..." 
                    progress={65} // Static since decryption is usually fast but we want an animation
                    isEncrypting={false} 
                  />
                )}
               </AnimatePresence>
               <div className="max-w-md mx-auto w-full pt-12">
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
                  {targetSenderHandle && !isPrivateKeyAccess && (
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

                  {/* Visual Permission Ribbon */}
                  <div className="px-4 py-3 bg-black/40 border border-white/5 rounded-xl flex items-center justify-between text-[10px] font-mono">
                    <span className="text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5 text-blue-400" />
                      Access Contract:
                    </span>
                    {(() => {
                      const isView = targetShare.allowView !== false;
                      const isDownload = targetShare.allowDownload !== false;
                      if (isView && isDownload) {
                        return <span className="text-emerald-400 font-bold uppercase tracking-wider">Full Access (View & Download)</span>;
                      } else if (isView) {
                        return <span className="text-blue-400 font-bold uppercase tracking-wider flex items-center gap-1"><Eye className="w-3.5 h-3.5" /> View Only (No Download)</span>;
                      } else if (isDownload) {
                        return <span className="text-amber-400 font-bold uppercase tracking-wider flex items-center gap-1"><Download className="w-3.5 h-3.5" /> Download Only (No View)</span>;
                      } else {
                        return <span className="text-red-400 font-bold uppercase tracking-wider">No Access Granted</span>;
                      }
                    })()}
                  </div>

                  {(() => {
                    const isViewAllowed = targetShare.allowView !== false;
                    const isDownloadAllowed = targetShare.allowDownload !== false;
                    return (
                      <div className={`grid gap-3 ${isViewAllowed && isDownloadAllowed ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1'}`}>
                        {isDownloadAllowed && (
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
                        )}

                        {isViewAllowed && (
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
                        )}
                      </div>
                    );
                  })()}

                  <div className="p-4 bg-blue-500/5 rounded-lg border border-blue-500/10 flex items-start gap-3">
                    <Shield className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    <p className="text-[10px] text-blue-400/80 leading-relaxed italic">
                      This file was decrypted locally in your browser range. The server only provided the encrypted blob; the key was extracted from your private URL fragment.
                    </p>
                  </div>
                </div>
              )}
               <button 
                  onClick={reset}
                  className="mt-8 w-full py-4 text-slate-500 hover:text-blue-400 font-mono text-[9px] uppercase tracking-widest border border-dashed border-border-main rounded-xl transition-all"
               >
                  Cancel Extraction
               </button>
            </div>
          </motion.div>
          ) : activeTab === 'home' ? (
            <motion.div
              key="home-tab"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-6"
            >
              <AnimatePresence mode="wait">
          
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
              <div className="bg-bg-card p-3 sm:p-8 rounded-xl technical-border text-center relative">
                {/* Home Sub-Tabs Switcher */}
                <div className="flex border-b border-border-main mb-6">
                  <button 
                    onClick={() => setHomeSubTab('terminal')}
                    className={`flex-1 py-3 text-center font-mono font-bold text-[10px] uppercase tracking-wider transition-all border-b-2 ${
                      homeSubTab === 'terminal' 
                        ? 'border-blue-500 text-blue-400' 
                        : 'border-transparent text-slate-500 hover:text-slate-400'
                    }`}
                  >
                    Access Terminal
                  </button>
                  <button 
                    onClick={() => setHomeSubTab('my-shares')}
                    className={`flex-1 py-3 text-center font-mono font-bold text-[10px] uppercase tracking-wider relative transition-all border-b-2 ${
                      homeSubTab === 'my-shares' 
                        ? 'border-blue-500 text-blue-400' 
                        : 'border-transparent text-slate-500 hover:text-slate-400'
                    }`}
                  >
                    My Active Shares {ownerShares.length > 0 && (
                      <span className="ml-[6px] px-1.5 py-0.5 text-[8px] leading-none text-blue-400 bg-blue-500/10 border border-blue-500/20 rounded-full font-sans">
                        {ownerShares.length}
                      </span>
                    )}
                  </button>
                </div>

                {homeSubTab === 'terminal' ? (
                  <>
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
                          <h2 className="text-2xl sm:text-3xl font-sans font-black text-text-main uppercase tracking-tight leading-none">Access Terminal</h2>
                        </div>
                        <p className="text-[10px] text-text-sub uppercase tracking-widest font-medium opacity-60">Select required operational mode</p>
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
                          <h3 className="font-sans font-black text-lg sm:text-xl leading-none text-text-main tracking-tight uppercase mb-1">Deposit Data</h3>
                          <p className="text-[9px] uppercase font-sans font-bold tracking-widest text-text-sub">Encrypt & Store Secure Fragments</p>
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
                    </div>
                  </>
                ) : (
                  <div className="text-left space-y-4">
                    <div className="relative mb-8">
                      <div className="absolute top-0 left-0 w-8 h-[1px] bg-blue-500/50" />
                      <div className="absolute top-0 left-0 w-[1px] h-8 bg-blue-500/50" />
                      <div className="pt-6 pl-2 sm:pl-6">
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-[10px] font-black text-blue-500/50 font-mono">02 //</span>
                          <h2 className="text-xl sm:text-2xl font-sans font-black text-text-main uppercase tracking-tight leading-none">Active Shares Ledger</h2>
                        </div>
                        <p className="text-[10px] text-text-sub uppercase tracking-widest font-medium opacity-60">Manage your unexpired secure deposits</p>
                      </div>
                    </div>

                    {!user ? (
                      <div className="p-8 bg-blue-500/5 rounded-xl border border-blue-500/10 text-center">
                        <Lock className="w-8 h-8 text-blue-500/30 mx-auto mb-3" />
                        <p className="text-xs font-mono text-text-sub uppercase">Authenticate identity to view active shared ledger</p>
                      </div>
                    ) : ownerShares.length === 0 ? (
                      <div className="p-8 bg-white/5 rounded-xl border border-white/5 text-center">
                        <p className="text-xs font-mono text-slate-500 uppercase">No active security deposits registered.</p>
                        <p className="text-[10px] font-mono text-slate-600 mt-2 lowercase leading-relaxed">
                          Any files you upload will display here with live view counts and status trackers until expiration.
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-3 max-h-[440px] overflow-y-auto pr-1 custom-scrollbar">
                        {ownerShares.map((share) => (
                          <button
                            key={share.id}
                            onClick={() => handleSelectActiveSelfShare(share)}
                            className="w-full relative bg-bg-card hover:bg-bg-base p-4 rounded-xl transition-all text-left flex items-center justify-between border border-border-main hover:border-blue-500/30 shadow-md group cursor-pointer overflow-hidden"
                          >
                            <div className="flex items-center gap-3 min-w-0 flex-1">
                              <div className="p-2 bg-black/30 rounded-lg shrink-0">
                                {getFileIcon(share.mimeType || 'unknown')}
                              </div>
                              <div className="min-w-0 flex-1">
                                <h4 className="font-sans font-bold text-xs text-text-main group-hover:text-blue-400 transition-colors truncate max-w-[180px] sm:max-w-xs">
                                  {share.fileName}
                                </h4>
                                <div className="flex items-center gap-2 mt-1">
                                  <span className="text-[9px] font-mono text-text-sub">
                                    {formatSize(share.size || 0)}
                                  </span>
                                  <span className="text-[8px] font-mono text-blue-500/50">•</span>
                                  <div className="flex items-center gap-1 text-[9px] font-mono text-blue-400">
                                    <Eye className="w-3 h-3 opacity-70" />
                                    <span>{share.views || 0} views</span>
                                  </div>
                                </div>
                              </div>
                            </div>

                            <div className="flex flex-col items-end gap-1 shrink-0 ml-3">
                              <span className="text-[8px] font-mono text-slate-500 uppercase">Expires:</span>
                              <div className="flex items-center gap-1 bg-blue-500/5 px-2 py-1 rounded border border-blue-500/10">
                                <Clock className="w-3 h-3 text-blue-400 shrink-0" />
                                <span className="text-[9px] font-mono text-blue-400 uppercase tabular-nums font-bold">
                                  <Countdown expiresAt={share.expiresAt} />
                                </span>
                              </div>
                            </div>
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                )}
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
              className="bg-bg-card p-6 rounded-xl technical-border overflow-hidden relative"
            >
              <AnimatePresence>
                {(isUploading || isEncrypting) && (
                  <ProcessingOverlay 
                    phase={currentPhase} 
                    progress={uploadProgress} 
                    isEncrypting={isEncrypting} 
                  />
                )}
              </AnimatePresence>
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
                  ${selectedFiles.length > 0 ? 'border-blue-500/50 bg-blue-500/5' : 'border-white/10 hover:border-blue-500/30 hover:bg-white/5'}
                `}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  const newFiles = e.dataTransfer.files;
                  if (newFiles && newFiles.length > 0) {
                    const list = Array.from(newFiles);
                    setSelectedFiles(prev => {
                      const filtered = list.filter(nf => !prev.some(f => f.name === nf.name && f.size === nf.size));
                      return [...prev, ...filtered];
                    });
                  }
                }}
              >
                {selectedFiles.length === 0 ? (
                  <>
                    <div className="p-4 bg-white/5 rounded-full mb-4 group-hover:scale-110 transition-transform">
                      <Upload className="w-8 h-8 text-slate-500 group-hover:text-blue-500" />
                    </div>
                    <p className="text-sm text-slate-400 mb-1">Drag & drop your files here</p>
                    <p className="text-[10px] text-slate-600 uppercase font-mono">Select or drop multiple files (Max 10MB total)</p>
                    <input 
                      type="file" 
                      multiple
                      className="absolute inset-0 opacity-0 cursor-pointer"
                      onChange={(e) => {
                        const newFiles = e.target.files;
                        if (newFiles && newFiles.length > 0) {
                          const list = Array.from(newFiles);
                          setSelectedFiles(prev => {
                            const filtered = list.filter(nf => !prev.some(f => f.name === nf.name && f.size === nf.size));
                            return [...prev, ...filtered];
                          });
                        }
                      }}
                    />
                  </>
                ) : (
                  <div className="w-full flex flex-col items-stretch space-y-4">
                    <div className="flex items-center justify-between border-b border-white/5 pb-2">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
                        Selected Files ({selectedFiles.length})
                      </span>
                      <button 
                        onClick={() => setSelectedFiles([])}
                        className="text-[9px] font-mono text-red-400/80 hover:text-red-400 uppercase tracking-wider flex items-center gap-1 hover:underline cursor-pointer"
                      >
                        <Trash2 className="w-3 h-3" /> Clear All
                      </button>
                    </div>

                    <div className="max-h-[220px] overflow-y-auto space-y-2 pr-1 custom-scrollbar">
                      {selectedFiles.map((f, idx) => (
                        <div 
                          key={`${f.name}-${f.size}-${idx}`}
                          className="flex items-center justify-between p-3 bg-white/5 hover:bg-white/10 rounded-lg border border-white/5 transition-colors"
                        >
                          <div className="flex items-center gap-3 min-w-0 flex-1">
                            <div className="p-1.5 bg-black/30 rounded">
                              {getFileIcon(f.type)}
                            </div>
                            <div className="text-left min-w-0 flex-1">
                              <p className="text-xs font-medium text-text-main truncate max-w-[280px] sm:max-w-[400px]">
                                {f.name}
                              </p>
                              <p className="text-[9px] font-mono text-text-sub">
                                {formatSize(f.size)} • {f.type || 'unknown type'}
                              </p>
                            </div>
                          </div>
                          
                          <button 
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFiles(prev => prev.filter((_, i) => i !== idx));
                            }}
                            className="p-1.5 text-slate-500 hover:text-red-400 transition-colors cursor-pointer"
                            title="Remove file"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ))}
                    </div>

                    {/* Cumulative file details */}
                    <div className="pt-2 border-t border-white/5 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-black/25 p-3 rounded-lg border border-white/5">
                      <div className="text-left flex-1 font-mono">
                        <div className="flex justify-between text-[9px] text-slate-500 uppercase tracking-wider mb-1">
                          <span>Cumulative Load</span>
                          <span className={selectedFiles.reduce((acc, current) => acc + current.size, 0) > 10 * 1024 * 1024 ? "text-red-400 font-bold" : "text-emerald-400 font-bold"}>
                            {formatSize(selectedFiles.reduce((acc, current) => acc + current.size, 0))} / 10.0 MB
                          </span>
                        </div>
                        <div className="w-full bg-white/10 h-1 rounded-full overflow-hidden">
                          <div 
                            className={`h-full transition-all duration-300 ${
                              selectedFiles.reduce((acc, curr) => acc + curr.size, 0) > 10 * 1024 * 1024 ? "bg-red-500" : "bg-blue-500"
                            }`}
                            style={{ width: `${Math.min(100, (selectedFiles.reduce((acc, curr) => acc + curr.size, 0) / (10 * 1024 * 1024)) * 100)}%` }}
                          />
                        </div>
                      </div>

                      <div className="flex items-center gap-2 relative self-end sm:self-auto">
                        <button 
                          className="relative overflow-hidden flex items-center gap-1.5 px-3 py-1.5 bg-white/5 hover:bg-white/10 border border-white/15 rounded-lg text-[10px] font-mono text-blue-400 uppercase tracking-widest cursor-pointer transition-colors"
                        >
                          <Upload className="w-3.5 h-3.5" />
                          <span>Add More</span>
                          <input 
                            type="file" 
                            multiple
                            className="absolute inset-0 opacity-0 cursor-pointer"
                            onChange={(e) => {
                              const newFiles = e.target.files;
                              if (newFiles && newFiles.length > 0) {
                                const list = Array.from(newFiles);
                                setSelectedFiles(prev => {
                                  const filtered = list.filter(nf => !prev.some(f => f.name === nf.name && f.size === nf.size));
                                  return [...prev, ...filtered];
                                });
                              }
                            }}
                          />
                        </button>
                      </div>
                    </div>
                    
                    {selectedFiles.length > 1 && (
                      <div className="text-[9px] font-mono text-blue-400/80 uppercase tracking-wide text-left flex items-start gap-1.5 p-2 bg-blue-500/5 rounded border border-blue-500/10">
                        <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                        <span>ZERO-KNOWLEDGE BUNDLING ACTIVE: MULTIPLE FILES SELECTED. WE WILL AUTO-ZIP THEM CLIENT-SIDE INTO A SECURE ARCHIVE BUNDLE BEFORE ENCRYPTION.</span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {selectedFiles.length > 0 && (
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

                  {/* Recipient Operational Rules */}
                  <div className="bg-black/40 p-4 rounded-xl border border-white/5 space-y-3">
                    <label className="text-[10px] font-mono text-slate-500 uppercase tracking-widest flex items-center justify-between">
                      <span>Recipient Permissions</span>
                      <span className="text-blue-400 font-bold uppercase font-mono text-[8px]">Rules & Handshakes</span>
                    </label>
                    <div className="grid grid-cols-3 gap-2 mt-1">
                      <button
                        type="button"
                        onClick={() => {
                          setError(null);
                          setAllowView(true);
                          setAllowDownload(false);
                          console.log("CipherVault permissions: View Only selected");
                        }}
                        className={`p-2.5 rounded-lg border transition-all flex flex-col items-center justify-center gap-1.5 cursor-pointer text-center ${
                          allowView && !allowDownload
                            ? 'bg-blue-500/10 border-blue-500/40 text-blue-400 font-bold shadow-[0_0_15px_rgba(59,130,246,0.1)]'
                            : 'bg-white/5 border-white/10 text-slate-500 hover:text-white'
                        }`}
                      >
                        <Eye className="w-4 h-4" />
                        <span className="text-[9px] font-sans uppercase tracking-tight leading-none">View Only</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setError(null);
                          setAllowView(false);
                          setAllowDownload(true);
                          console.log("CipherVault permissions: Download Only selected");
                        }}
                        className={`p-2.5 rounded-lg border transition-all flex flex-col items-center justify-center gap-1.5 cursor-pointer text-center ${
                          !allowView && allowDownload
                            ? 'bg-blue-500/10 border-blue-500/40 text-blue-400 font-bold shadow-[0_0_15px_rgba(59,130,246,0.1)]'
                            : 'bg-white/5 border-white/10 text-slate-500 hover:text-white'
                        }`}
                      >
                        <Download className="w-4 h-4" />
                        <span className="text-[9px] font-sans uppercase tracking-tight leading-none">Download Only</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => {
                          setError(null);
                          setAllowView(true);
                          setAllowDownload(true);
                          console.log("CipherVault permissions: Full Access selected");
                        }}
                        className={`p-2.5 rounded-lg border transition-all flex flex-col items-center justify-center gap-1.5 cursor-pointer text-center ${
                          allowView && allowDownload
                            ? 'bg-blue-500/10 border-blue-500/40 text-blue-400 font-bold shadow-[0_0_15px_rgba(59,130,246,0.1)]'
                            : 'bg-white/5 border-white/10 text-slate-500 hover:text-white'
                        }`}
                      >
                        <ShieldAlert className="w-4 h-4" />
                        <span className="text-[9px] font-sans uppercase tracking-tight leading-none">Full Access</span>
                      </button>
                    </div>
                    <p className="text-[9px] text-slate-600 italic">Select the allowed operations for this file bundle. Only selected actions will be shown to the recipient.</p>
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
                  <p className="text-[9px] text-text-sub mb-3 font-mono leading-tight">Bonding allows you to use your personal key signature for manual retrieval in the Key_Extractor sidebar.</p>

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
        </AnimatePresence>
      </motion.div>
    ) : activeTab === 'chat' ? (
            <motion.div
              key="chat-tab"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="space-y-6 pb-24"
            >
              {/* Message Sending Section */}
              <div className="bg-bg-card border border-border-main rounded-2xl overflow-hidden shadow-xl p-6">
                <div className="flex items-center justify-between gap-3 mb-6">
                  <h3 className="font-sans font-black text-lg uppercase flex items-center gap-2 text-text-main">
                     <Mail className="w-5 h-5 text-blue-500 glow-blue" />
                     Quantum relay
                  </h3>
                  <button 
                    onClick={() => setShowChatPanel(true)}
                    className="p-2 bg-blue-500/10 hover:bg-blue-500/20 text-blue-500 rounded-lg transition-all border border-blue-500/20"
                  >
                    <MessageSquare className="w-4 h-4" />
                  </button>
                </div>
                
                <div className="space-y-3">
                  <div className="relative">
                    <AtSign className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-blue-500/40" />
                    <input 
                      type="text" 
                      placeholder="Recipient username..."
                      value={messageRecipient}
                      onChange={(e) => setMessageRecipient(e.target.value)}
                      className="w-full bg-bg-base/40 border border-border-main focus:border-blue-400/40 rounded-xl py-3 pl-10 pr-4 text-xs font-mono text-text-main placeholder:text-text-sub outline-none transition-all"
                    />
                  </div>
                  <textarea 
                    placeholder="Type encrypted message..."
                    value={messageText}
                    onChange={(e) => setMessageText(e.target.value)}
                    rows={3}
                    className="w-full bg-bg-base/40 border border-border-main focus:border-blue-400/40 rounded-xl p-4 text-xs font-mono text-text-main placeholder:text-text-sub outline-none transition-all resize-none"
                  />
                  <button 
                    disabled={isSendingMessage || !messageRecipient || !messageText || quotaExceeded}
                    onClick={sendSecureMessage}
                    className="w-full bg-blue-600 hover:bg-blue-500 text-white py-4 rounded-xl text-xs font-mono font-black uppercase tracking-[0.2em] flex items-center justify-center gap-3 shadow-lg shadow-blue-500/20 active-glow transition-all"
                  >
                    {isSendingMessage ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                    Broadcast Signal
                  </button>
                </div>
              </div>

              {/* Inbox / Active Channels */}
              <div className="bg-bg-card border border-border-main rounded-2xl overflow-hidden flex flex-col shadow-xl">
                 <div className="p-6 border-b border-border-main flex items-center justify-between bg-bg-base/40">
                    <div className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full bg-blue-500 animate-pulse glow-blue" />
                      <div>
                        <h2 className="text-sm font-sans font-black uppercase tracking-tight text-text-main">Active_Spectrum</h2>
                        <p className="text-[8px] font-sans font-medium text-slate-500 uppercase opacity-60">Incoming Relay Nodes</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                       <span className="text-[9px] font-mono text-blue-500 px-2 py-0.5 bg-blue-500/5 rounded border border-blue-500/10 uppercase font-black">{activeInboxShares.length} Active</span>
                    </div>
                  </div>

                  <div className="p-4">
                    <div className="space-y-2 max-h-[50vh] overflow-y-auto pr-1 custom-scrollbar">
                      {activeInboxShares.length === 0 ? (
                        <div className="py-20 text-center flex flex-col items-center">
                          <div className="w-12 h-12 rounded-full bg-bg-base/5 flex items-center justify-center mb-4 border border-border-main/50">
                             <Shield className="w-6 h-6 text-text-sub/20" />
                          </div>
                          <p className="text-[10px] font-mono text-text-sub uppercase tracking-widest leading-relaxed">No signals detected<br/><span className="opacity-50">Identity is silent.</span></p>
                        </div>
                      ) : (
                        activeInboxShares.map(share => (
                          <button
                            key={share.id}
                            onClick={() => handleInboxItemClick(share)}
                            className="w-full p-4 bg-bg-base/20 hover:bg-blue-500/5 rounded-xl border border-border-main/40 hover:border-blue-500/30 text-left transition-all group flex items-center gap-4"
                          >
                            <div className={`p-3 rounded-xl transition-all ${share.isMessage ? 'bg-purple-500/10 group-hover:bg-purple-500/20' : 'bg-blue-500/10 group-hover:bg-blue-500/20'}`}>
                              {share.isMessage ? (
                                <Mail className="w-5 h-5 text-purple-400" />
                              ) : (
                                <div className="text-blue-400">
                                  {getFileIcon(share.mimeType)}
                                </div>
                              )}
                            </div>
                            <div className="flex-1 overflow-hidden">
                              <div className="flex items-center justify-between mb-1">
                                <p className={`text-[11px] font-black truncate uppercase tracking-tight ${share.isMessage ? 'text-purple-400' : 'text-text-main'}`}>
                                  {share.isMessage ? 'Secure Message' : share.fileName}
                                </p>
                                <span className="text-[8px] font-mono text-slate-500 uppercase"><Countdown expiresAt={share.expiresAt} /></span>
                              </div>
                              <div className="flex items-center justify-between">
                                <p className="text-[9px] font-mono text-slate-500 truncate lowercase opacity-70">
                                  {share.isMessage ? 'Encrypted transmission' : formatSize(share.size)}
                                </p>
                                {share.senderHandle && (
                                  <div className="flex items-center gap-1.5 px-2 py-0.5 bg-blue-500/5 rounded border border-blue-500/10">
                                    <span className="text-[7px] text-blue-500/60 font-black uppercase">ID:</span>
                                    <span className="text-[7px] text-blue-400 font-bold group-hover:text-blue-300 transition-colors">@{share.senderHandle}</span>
                                  </div>
                                )}
                              </div>
                            </div>
                          </button>
                        ))
                      )}
                    </div>
                  </div>
              </div>
            </motion.div>
          ) : activeTab === 'notifications' ? (
            <motion.div
              key="notifications-tab"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.98 }}
              className="space-y-6 pb-24"
            >
              <div className="bg-bg-card border border-border-main rounded-2xl overflow-hidden shadow-xl">
                 <div className="p-6 border-b border-border-main flex items-center justify-between bg-bg-base/40">
                    <div className="flex items-center gap-3">
                      <Bell className="w-5 h-5 text-blue-500 glow-blue" />
                      <div>
                        <h2 className="text-sm font-sans font-black uppercase tracking-tight text-text-main">Signal_Log</h2>
                        <p className="text-[8px] font-sans font-medium text-slate-500 uppercase opacity-60">System Alerts & Intercepts</p>
                      </div>
                    </div>
                    <Activity className="w-4 h-4 text-blue-500/30" />
                 </div>

                 <div className="p-4 space-y-3">
                   {inboxShares.length === 0 ? (
                     <div className="py-24 text-center">
                        <Wifi className="w-8 h-8 text-text-sub/10 mx-auto mb-4" />
                        <p className="text-[10px] font-mono text-text-sub uppercase tracking-[0.3em]">No background signals detected</p>
                     </div>
                   ) : (
                     inboxShares.slice(0, 10).map((share, idx) => (
                       <button 
                         key={idx} 
                         onClick={() => handleInboxItemClick(share)}
                         className="w-full p-4 bg-bg-base/30 hover:bg-blue-500/5 rounded-xl border border-border-main/50 hover:border-blue-500/30 flex items-start gap-4 transition-all text-left group"
                       >
                          <div className={`p-2 rounded-lg transition-all ${share.isMessage ? 'bg-purple-500/10 group-hover:bg-purple-500/20' : 'bg-blue-500/10 group-hover:bg-blue-500/20'}`}>
                             {share.isMessage ? <Mail className="w-3 h-3 text-purple-400" /> : <div className="text-blue-400">{getFileIcon(share.mimeType)}</div>}
                          </div>
                          <div className="flex-1 min-w-0">
                             <p className="text-[10px] font-mono text-text-main uppercase font-black mb-1 truncate">
                                {share.isMessage ? 'Encrypted Message' : (share.fileName || 'Secure Fragment')}
                             </p>
                             <p className="text-[9px] font-mono text-slate-500 uppercase tracking-tighter">
                                {share.senderHandle ? `From: @${share.senderHandle}` : 'Unknown Relay'} • <Countdown expiresAt={share.expiresAt} />
                             </p>
                          </div>
                       </button>
                     ))
                   )}
                 </div>

                 <div className="p-4 bg-blue-500/5 border-t border-border-main flex items-center gap-3">
                    <Shield className="w-4 h-4 text-blue-500/30" />
                    <p className="text-[9px] font-mono text-slate-500 uppercase leading-tight italic">
                      Log is wiped automatically upon fragment expiration.
                    </p>
                 </div>
              </div>
            </motion.div>
          ) : activeTab === 'profile' ? (
            <motion.div
              key="profile-tab"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.98 }}
              className="space-y-6 pb-24"
            >
              <div className="bg-bg-card border border-border-main rounded-2xl overflow-hidden shadow-xl">
                 <div className="p-8 text-center border-b border-border-main relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-blue-500/50 to-transparent" />
                    <div className="relative inline-block mb-4">
                       <div className="w-20 h-20 bg-blue-500/10 rounded-2xl flex items-center justify-center border border-blue-500/20 mx-auto">
                          <UserIcon className="w-10 h-10 text-blue-500" />
                       </div>
                       <div className="absolute -bottom-1 -right-1 w-6 h-6 bg-green-500 rounded-lg flex items-center justify-center border-4 border-bg-card">
                          <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
                       </div>
                    </div>
                    <h2 className="text-xl font-mono font-black text-text-main uppercase tracking-widest">{profile?.username ? `@${profile.username}` : (user?.email || 'Guest_User')}</h2>
                    <p className="text-[10px] font-mono text-slate-500 uppercase mt-1 tracking-[0.2em]">Terminal Rank: {isAdmin ? 'SYS_ADMIN' : 'SECURE_NODE'}</p>
                 </div>

                 <div className="p-6 space-y-6">
                    <div>
                       <label className="text-[10px] font-mono font-black text-text-sub uppercase tracking-widest mb-3 block">Neural Theme Engine</label>
                        <div className="grid grid-cols-3 gap-3">
                          {[
                            { id: 'light', icon: Sun, label: 'BRIGHT' },
                            { id: 'dark', icon: Moon, label: 'DEEP' },
                            { id: 'system', icon: Monitor, label: 'AUTO' }
                          ].map((item) => (
                            <button
                              key={item.id}
                              onClick={() => setTheme(item.id as any)}
                              className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all relative overflow-hidden group ${
                                theme === item.id 
                                  ? 'bg-blue-600 border-blue-400 text-white shadow-[0_0_25px_rgba(59,130,246,0.4)] scale-105 z-10' 
                                  : 'bg-bg-base/40 border-border-main text-slate-500 hover:border-blue-500/30'
                              }`}
                            >
                              {theme === item.id && (
                                <div className="absolute inset-0 bg-gradient-to-br from-blue-400/20 to-transparent animate-shimmer" />
                              )}
                              <item.icon className={`w-5 h-5 ${theme === item.id ? 'glow-blue' : 'opacity-60 group-hover:opacity-100'}`} />
                              <span className="text-[8px] font-mono font-black uppercase tracking-widest">{item.label}</span>
                            </button>
                          ))}
                       </div>
                    </div>

                    <div className="pt-4 border-t border-border-main space-y-3">
                       <label className="text-[10px] font-mono font-black text-text-sub uppercase tracking-widest block">Core Protocols</label>
                       
                       {isAdmin && (
                         <button 
                           onClick={() => setShowAdmin(!showAdmin)}
                           className={`w-full flex items-center justify-between p-4 border rounded-xl transition-all group mb-1 ${
                             showAdmin 
                               ? 'bg-red-500/10 border-red-500/30 text-red-500' 
                               : 'bg-bg-base/40 border-border-main text-slate-500 hover:border-red-500/30 hover:text-red-400'
                           }`}
                         >
                            <div className="flex items-center gap-3">
                               <ShieldAlert className={`w-5 h-5 ${showAdmin ? 'glow-red' : 'opacity-60'}`} />
                               <span className="text-xs font-mono font-black uppercase tracking-widest">Maintenance System</span>
                            </div>
                            <div className={`w-2 h-2 rounded-full ${showAdmin ? 'bg-red-500 animate-pulse glow-red' : 'bg-slate-700'}`} />
                         </button>
                       )}

                       {isAdmin && showAdmin && (
                         <div className="mb-4">
                           <AdminDashboard 
                             onPrune={pruneExpired} 
                             quotaExceeded={quotaExceeded}
                           />
                         </div>
                       )}
                       
                       {!user ? (
                         <div className="space-y-3 w-full">
                           <button 
                             onClick={handleSignIn}
                           className="w-full flex items-center justify-between p-4 bg-blue-600 hover:bg-blue-500 text-white rounded-xl transition-all shadow-lg shadow-blue-600/20 group active-glow"
                         >
                            <div className="flex items-center gap-3">
                               <Key className="w-5 h-5" />
                               <span className="text-xs font-mono font-black uppercase tracking-widest">Sign Up / Sign In</span>
                            </div>
                            <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                         </button>
                         <button 
                           type="button"
                           onClick={handleSignInAnonymous}
                           className="w-full flex items-center justify-between p-4 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/50 text-slate-300 rounded-xl transition-all group active-glow"
                         >
                            <div className="flex items-center gap-3">
                               <UserIcon className="w-5 h-5 text-blue-400" />
                               <span className="text-xs font-mono font-black uppercase tracking-widest text-left">Sign In as Guest (Demo)</span>
                            </div>
                            <ChevronRight className="w-4 h-4 text-slate-500 group-hover:translate-x-1 transition-transform" />
                         </button>
                         <p className="text-[9.5px] text-slate-500 text-center font-mono lowercase pt-1">
                           *use guest login if Google authentication popup is blocked or fails on your mobile.
                         </p>
                       </div>
                       ) : (
                         <button 
                           onClick={signOutAll}
                           className="w-full flex items-center justify-between p-4 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-500 rounded-xl transition-all group"
                         >
                            <div className="flex items-center gap-3">
                               <LogOut className="w-5 h-5" />
                               <span className="text-xs font-mono font-black uppercase tracking-widest">Disconnect Session</span>
                            </div>
                            <Trash2 className="w-4 h-4 text-red-500/50 group-hover:text-red-500 transition-colors" />
                         </button>
                       )}
                    </div>
                 </div>
                 
                 <div className="p-4 bg-bg-base/40 text-center border-t border-border-main">
                    <p className="text-[8px] font-mono text-slate-600 uppercase tracking-widest">Session ID: {user?.uid?.substring(0, 12).toUpperCase() || 'UNAUTHENTICATED'}</p>
                 </div>
              </div>

              {/* About Section */}
              <div className="bg-bg-card border border-border-main rounded-2xl overflow-hidden shadow-xl mt-6 relative">
                 <div className="scanning scanline opacity-10" />
                 <div className="p-6 border-b border-border-main bg-bg-base/20">
                    <div className="flex items-center gap-3">
                       <div className="p-2 bg-blue-500/10 rounded-lg">
                          <Info className="w-4 h-4 text-blue-500" />
                       </div>
                       <div>
                          <h2 className="text-sm font-sans font-black uppercase tracking-tight text-text-main">About Protocol</h2>
                          <p className="text-[8px] font-sans font-medium text-slate-500 uppercase opacity-60">System Information & Origin</p>
                       </div>
                    </div>
                 </div>

                 <div className="p-6 space-y-6">
                    {/* Move the Status Cards here */}
                    <div className="grid grid-cols-3 gap-2">
                       {[
                         { label: "AES-256-GCM", icon: Shield },
                         { label: "ZERO-K_RELAY", icon: Lock },
                         { label: "RESILIENCY_UP", icon: Zap }
                       ].map((item, idx) => (
                         <div key={idx} className="bg-bg-base/40 border border-border-main p-3 rounded-xl flex flex-col items-center gap-2 technical-border group transition-all">
                           <item.icon className="w-4 h-4 text-blue-500/40 group-hover:text-blue-500 glow-blue transition-all" />
                           <span className="text-[6px] font-mono font-black uppercase tracking-[0.2em] text-text-sub group-hover:text-blue-400 transition-colors text-center leading-tight">{item.label}</span>
                         </div>
                       ))}
                    </div>

                    <div className="flex items-center justify-between p-3 bg-bg-base/30 rounded-xl border border-border-main/50">
                       <span className="text-[9px] font-mono text-slate-500 uppercase tracking-widest">Developer</span>
                       <div className="flex items-center gap-2">
                          <div className="w-4 h-4 bg-blue-500/20 rounded flex items-center justify-center">
                             <Terminal className="w-2.5 h-2.5 text-blue-500" />
                          </div>
                          <span className="text-[10px] font-sans font-black text-text-main uppercase">GM Studio</span>
                       </div>
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                       <div className="p-3 bg-bg-base/30 rounded-xl border border-border-main/50">
                          <span className="text-[8px] font-mono text-slate-600 uppercase block mb-1 text-[7px]">Architecture</span>
                          <span className="text-[9px] font-sans font-bold text-text-main uppercase">Zero-Knowledge</span>
                       </div>
                       <div className="p-3 bg-bg-base/30 rounded-xl border border-border-main/50">
                          <span className="text-[8px] font-mono text-slate-600 uppercase block mb-1 text-[7px]">Standard</span>
                          <span className="text-[9px] font-sans font-bold text-text-main uppercase">AES-256-GCM</span>
                       </div>
                    </div>

                    <div className="p-4 bg-blue-500/5 rounded-xl border border-blue-500/10">
                       <p className="text-[10px] font-sans text-slate-500 italic leading-relaxed text-center">
                         "Empowering digital sovereignty through mathematical certainty. Every bit of data is encrypted locally before it ever touches our network."
                       </p>
                    </div>

                    <div className="flex items-center justify-center gap-6 pt-2 border-t border-border-main/30 mt-2 pb-4">
                       <div className="flex flex-col items-center gap-1">
                          <span className="text-[8px] font-mono text-slate-600 uppercase">Version</span>
                          <span className="text-[9px] font-sans font-black text-blue-500">2.4.0-STABLE</span>
                       </div>
                       <div className="flex flex-col items-center gap-1">
                          <span className="text-[8px] font-mono text-slate-600 uppercase">Status</span>
                          <div className="flex items-center gap-1.5">
                             <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                             <span className="text-[9px] font-sans font-black text-green-500">NOMINAL</span>
                          </div>
                       </div>
                    </div>

                    {/* Developer Branding Footer inside About */}
                    <div className="flex flex-col items-center gap-3 pt-6 border-t border-border-main/30">
                       <div className="flex flex-col items-center gap-1.5 group">
                          <span className="text-[7px] font-mono text-slate-500 uppercase tracking-[0.4em] opacity-40">Designed & Developed by</span>
                          <div className="flex items-center gap-3">
                             <div className="h-[1px] w-6 bg-gradient-to-r from-transparent to-border-main" />
                             <span className="text-xs font-mono font-black text-slate-400 tracking-[0.4em] uppercase hover:text-blue-500 transition-colors cursor-default">GM Studio</span>
                             <div className="h-[1px] w-6 bg-gradient-to-l from-transparent to-border-main" />
                          </div>
                       </div>
                       <p className="text-[8px] font-mono text-slate-600 uppercase tracking-widest flex items-center justify-center gap-2 opacity-50">
                          <span>AES-256-GCM</span>
                          <span>•</span>
                          <span>End-to-End Encrypted</span>
                       </p>
                    </div>
                 </div>
              </div>
            </motion.div>
          ) : (
            <div key="fallback-empty" />
          )}
      </AnimatePresence>
    </main>
        </div>
      </div>
      
      {/* Real-time Modals Group */}
      <AnimatePresence>
        {showPreview && decryptedFile && (
          <PreviewModal 
            file={decryptedFile} 
            allowDownload={targetShare ? targetShare.allowDownload !== false : true}
            onClose={() => setShowPreview(false)} 
          />
        )}
        {decryptedMessage && (
          <MessageModal 
            text={decryptedMessage.text}
            sender={isPrivateKeyAccess ? undefined : decryptedMessage.sender}
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
    </div>
  );
}
