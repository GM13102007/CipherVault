import React, { useState, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  BookOpen,
  Download,
  Upload,
  X,
  Search,
  Shield,
  Lock,
  Key,
  MessageSquare,
  CheckCircle2,
  Sparkles,
  Printer,
  Copy,
  Check,
  HelpCircle,
  Zap,
} from "lucide-react";
import jsPDF from "jspdf";
import html2canvas from "html2canvas";

interface UserManualModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const UserManualModal: React.FC<UserManualModalProps> = ({ isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [isGeneratingPdf, setIsGeneratingPdf] = useState(false);
  const [copiedStep, setCopiedStep] = useState<string | null>(null);

  const manualContentRef = useRef<HTMLDivElement>(null);

  if (!isOpen) return null;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedStep(id);
    setTimeout(() => setCopiedStep(null), 2000);
  };

  const generateDirectPdf = () => {
    const pdf = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4"
    });

    const pageWidth = 210;
    const pageHeight = 297;
    const margin = 15;
    const contentWidth = pageWidth - margin * 2;

    let y = 15;

    // Background dark rectangle
    pdf.setFillColor(15, 23, 42); // #0f172a
    pdf.rect(0, 0, pageWidth, pageHeight, "F");

    // Title Header
    pdf.setTextColor(255, 255, 255);
    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(18);
    pdf.text("CIPHERVAULT USER MANUAL", margin, y + 5);

    y += 12;
    pdf.setFontSize(10);
    pdf.setFont("helvetica", "normal");
    pdf.setTextColor(59, 130, 246); // Blue
    pdf.text("Zero-Knowledge E2EE File Sharing & Quantum Messenger Protocol", margin, y);

    y += 8;
    pdf.setDrawColor(51, 65, 85);
    pdf.line(margin, y, pageWidth - margin, y);
    y += 10;

    const sections = [
      {
        title: "1. What is CipherVault? (Overview)",
        text: [
          "CipherVault is a Zero-Knowledge, End-to-End Encrypted File & Secret Message Sharing Platform.",
          "All data is encrypted client-side inside your web browser BEFORE being transmitted to servers.",
          "• Zero-Knowledge: Neither servers nor admins can access private keys or decrypted content.",
          "• AES-256-GCM: State-of-the-art cryptographic standard utilized by financial institutions.",
          "• Auto-Expiring Shares: Uploaded files automatically destroy themselves after set timer."
        ]
      },
      {
        title: "2. How to Encrypt & Send Files (Step-by-Step)",
        text: [
          "1. Choose File: Click 'Select File' on the home dashboard or drag & drop files.",
          "2. Expiry Timer: Select how long file stays active (5 Min, 1 Hour, 24 Hours).",
          "3. Permissions: Enable 'Allow View' for live streaming or 'Allow Download' for saving.",
          "4. Encrypt & Transmit: Click 'Encrypt & Transmit' to lock file using client AES-256.",
          "5. Share Link: Copy generated link (embeds secret key safely in URL fragment #) or key."
        ]
      },
      {
        title: "3. How to Receive & Decrypt Files",
        text: [
          "Method A (Direct Link): Open share link in browser. Secret key extracts automatically.",
          "Method B (Manual Key): Click KEY / SECURE_ID icon, paste 15-character key, click Execute Recovery."
        ]
      },
      {
        title: "4. Direct Quantum Messenger & Private Messaging",
        text: [
          "• Access Chat section in navigation menu.",
          "• Search or enter contact handle (e.g., @username).",
          "• Type confidential message. Text encrypts client-side prior to transport.",
          "• Supports self-destructing message rules for maximum privacy."
        ]
      },
      {
        title: "5. Profile & Custom Private Key Vault",
        text: [
          "• Custom Key Generator: Create unique 12 to 20 character security keys.",
          "• Key Vault Storage: Access historical keys securely inside session storage.",
          "• Authentication: Sign in via Google OAuth or keep Anonymous Quantum Session."
        ]
      },
      {
        title: "6. Frequently Asked Questions (FAQ)",
        text: [
          "Q: Can server administrators intercept files?",
          "A: No. Encryption occurs inside browser prior to transport. Server only holds encrypted blocks.",
          "Q: What happens when timer reaches zero?",
          "A: Encrypted payload is permanently deleted from storage.",
          "Q: Why is key in URL fragment (#)?",
          "A: Text after '#' is never sent in HTTP requests to web servers."
        ]
      }
    ];

    sections.forEach((sec) => {
      if (y > pageHeight - 40) {
        pdf.addPage();
        pdf.setFillColor(15, 23, 42);
        pdf.rect(0, 0, pageWidth, pageHeight, "F");
        y = 20;
      }

      // Section Title Box
      pdf.setFillColor(30, 41, 59);
      pdf.rect(margin, y, contentWidth, 8, "F");
      pdf.setFont("helvetica", "bold");
      pdf.setFontSize(11);
      pdf.setTextColor(255, 255, 255);
      pdf.text(sec.title, margin + 3, y + 5.5);
      y += 12;

      pdf.setFont("helvetica", "normal");
      pdf.setFontSize(9);
      pdf.setTextColor(203, 213, 225);

      sec.text.forEach((line) => {
        if (y > pageHeight - 20) {
          pdf.addPage();
          pdf.setFillColor(15, 23, 42);
          pdf.rect(0, 0, pageWidth, pageHeight, "F");
          y = 20;
        }
        const wrappedLines = pdf.splitTextToSize(line, contentWidth - 5);
        pdf.text(wrappedLines, margin + 2, y);
        y += wrappedLines.length * 5;
      });

      y += 4;
    });

    // Footer
    pdf.setFontSize(8);
    pdf.setTextColor(100, 116, 139);
    pdf.text("CipherVault E2EE Security Protocol • Zero-Knowledge Architecture Guaranteed", margin, pageHeight - 10);

    pdf.save("CipherVault_User_Manual_Guide.pdf");
  };

  const handleDownloadPdf = async () => {
    setIsGeneratingPdf(true);
    try {
      const element = manualContentRef.current;
      if (!element) {
        generateDirectPdf();
        return;
      }

      const pdf = new jsPDF({
        orientation: "portrait",
        unit: "mm",
        format: "a4"
      });

      const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        logging: false,
        backgroundColor: "#0f172a",
        onclone: (clonedDoc) => {
          // Replace oklch in all style elements to prevent html2canvas parsing crashes
          const styleElements = clonedDoc.querySelectorAll("style");
          styleElements.forEach((styleEl) => {
            if (styleEl.textContent && styleEl.textContent.includes("oklch")) {
              styleEl.textContent = styleEl.textContent.replace(/oklch\([^)]+\)/gi, "rgb(59, 130, 246)");
            }
          });

          // Also check all elements in the cloned document for inline oklch styles
          const allElements = clonedDoc.querySelectorAll("*");
          allElements.forEach((el) => {
            if (el instanceof HTMLElement) {
              const styleAttr = el.getAttribute("style");
              if (styleAttr && styleAttr.includes("oklch")) {
                el.setAttribute("style", styleAttr.replace(/oklch\([^)]+\)/gi, "rgb(59, 130, 246)"));
              }
            }
          });
        }
      });

      const imgData = canvas.toDataURL("image/png");
      const imgWidth = 210;
      const pageHeight = 297;
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      let heightLeft = imgHeight;
      let position = 0;

      pdf.addImage(imgData, "PNG", 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;

      while (heightLeft >= 0) {
        position = heightLeft - imgHeight;
        pdf.addPage();
        pdf.addImage(imgData, "PNG", 0, position, imgWidth, imgHeight);
        heightLeft -= pageHeight;
      }

      pdf.save("CipherVault_User_Manual_Guide.pdf");
    } catch (err) {
      console.warn("html2canvas PDF generation failed, executing direct jsPDF manual generator:", err);
      generateDirectPdf();
    } finally {
      setIsGeneratingPdf(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const manualSections = [
    {
      id: "intro",
      icon: Shield,
      category: "overview",
      title: "1. What is CipherVault? (Overview)",
      summary: "Understand the zero-knowledge client-side AES-256-GCM encryption architecture.",
      content: (
        <div className="space-y-3 text-xs leading-relaxed text-slate-300">
          <p>
            <strong>CipherVault</strong> is a <em>Zero-Knowledge, End-to-End Encrypted File & Secret Message Sharing Platform</em> designed for global security and ease of use.
            All data is encrypted client-side inside your browser <strong>BEFORE</strong> being uploaded.
          </p>
          <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-xl space-y-1.5">
            <div className="font-bold text-blue-400 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-blue-400" />
              <span>Core Pillars of Security:</span>
            </div>
            <ul className="list-disc pl-4 space-y-1 text-slate-300">
              <li><strong>Zero-Knowledge:</strong> Neither servers nor administrators can access your private key or read decrypted content.</li>
              <li><strong>Military-Grade AES-256-GCM:</strong> State-of-the-art cryptographic standard utilized by financial institutions worldwide.</li>
              <li><strong>Auto-Expiring Shares:</strong> Uploaded files automatically destroy themselves after your selected timer (5 min to 24 hours).</li>
            </ul>
          </div>
        </div>
      )
    },
    {
      id: "send_file",
      icon: Upload,
      category: "sending",
      title: "2. How to Encrypt & Send Files (Step-by-Step)",
      summary: "Complete walkthrough for selecting files, setting access controls, and generating secure share links.",
      content: (
        <div className="space-y-3 text-xs leading-relaxed text-slate-300">
          <ol className="list-decimal pl-4 space-y-2.5">
            <li>
              <strong>Choose File:</strong> On the home dashboard, click <em>Select File</em> or drop any document, photo, video, or archive.
            </li>
            <li>
              <strong>Configure Expiry Timer:</strong> Select how long the secure share stays active (e.g., 5 Minutes, 1 Hour, or 24 Hours).
            </li>
            <li>
              <strong>Set Permission Controls:</strong>
              <div className="mt-1 p-2 bg-slate-900 border border-slate-800 rounded-lg text-[11px] space-y-1 text-slate-300">
                <div>• <strong>Allow View:</strong> Permits the recipient to stream image, PDF, audio, or video live in the secure browser player.</div>
                <div>• <strong>Allow Download:</strong> Grants permission for the recipient to save the decrypted file locally.</div>
              </div>
            </li>
            <li>
              <strong>Encrypt & Transmit:</strong> Click <strong>"Encrypt & Transmit"</strong>. Your browser locks the file using AES-256 and transmits encrypted chunks.
            </li>
            <li>
              <strong>Share Secure Link or Key:</strong> Copy the generated link (which embeds the secret key safely in the URL fragment <code>#key=...</code>) or send the 15-character key directly.
            </li>
          </ol>
        </div>
      )
    },
    {
      id: "receive_file",
      icon: Download,
      category: "receiving",
      title: "3. How to Receive & Decrypt Files",
      summary: "How recipients unlock links, enter secret recovery keys, preview content, or save files.",
      content: (
        <div className="space-y-3 text-xs leading-relaxed text-slate-300">
          <div className="space-y-2">
            <p className="font-bold text-blue-400">Method A: Direct Link Access</p>
            <p className="pl-3 border-l-2 border-blue-500 text-slate-300">
              Open the share link in any browser. CipherVault automatically reads the embedded decryption key from the URL hash fragment and presents instant <strong>"Decrypt & View"</strong> or <strong>"Decrypt & Download"</strong> options.
            </p>

            <p className="font-bold text-amber-400 mt-3">Method B: Manual 15-Character Key Recovery</p>
            <p className="pl-3 border-l-2 border-amber-500 text-slate-300">
              Click the <strong>KEY / SECURE_ID</strong> recovery icon on the left panel, paste your 15-character key (e.g., <code>A#3f-L9!xZ2*q7</code>), and click <strong>Execute Recovery</strong>.
            </p>
          </div>
        </div>
      )
    },
    {
      id: "chat_sec",
      icon: MessageSquare,
      category: "chat",
      title: "4. Direct Quantum Messenger & Private Messaging",
      summary: "Send direct end-to-end encrypted secret text messages to any user handle.",
      content: (
        <div className="space-y-3 text-xs leading-relaxed text-slate-300">
          <p>
            CipherVault features a built-in <strong>E2EE Quantum Messenger</strong> for real-time secure communication:
          </p>
          <ul className="list-disc pl-4 space-y-1.5">
            <li>Navigate to the <strong>Chat</strong> section in the main navigation.</li>
            <li>Search or select a contact handle (e.g., <code>@username</code>).</li>
            <li>Type your confidential message and hit Send. Text is encrypted on your client device prior to transport.</li>
            <li>Messages support self-destruction rules for supreme privacy hygiene.</li>
          </ul>
        </div>
      )
    },
    {
      id: "keys_profile",
      icon: Key,
      category: "keys",
      title: "5. Profile & Custom Private Key Vault",
      summary: "Manage user handles, generate unique personal keys, and view key history.",
      content: (
        <div className="space-y-3 text-xs leading-relaxed text-slate-300">
          <p>
            Under your <strong>Profile</strong> tab, you can personalize handles and cryptographic credentials:
          </p>
          <ul className="list-disc pl-4 space-y-1 text-slate-300">
            <li><strong>Custom Key Generator:</strong> Create unique 12 to 20 character security keys to tie to file uploads.</li>
            <li><strong>Key Vault Storage:</strong> Access your historical keys securely in your session storage for fast retrieval.</li>
            <li><strong>Authentication:</strong> Authenticate seamlessly via Google OAuth or keep an Anonymous Quantum Session.</li>
          </ul>
        </div>
      )
    },
    {
      id: "faq_security",
      icon: HelpCircle,
      category: "faq",
      title: "6. Frequently Asked Questions & Troubleshooting",
      summary: "Answers to common security, link, and storage inquiries.",
      content: (
        <div className="space-y-3 text-xs leading-relaxed text-slate-300">
          <div className="space-y-2">
            <div className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
              <strong className="text-blue-400">Q: Can server administrators or third parties intercept my files?</strong>
              <p className="mt-1 text-slate-300">No. Encryption happens strictly inside your web browser prior to transmission. Servers only store unreadable scrambled cipher data blocks.</p>
            </div>
            <div className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
              <strong className="text-blue-400">Q: What happens when the expiry timer reaches zero?</strong>
              <p className="mt-1 text-slate-300">The file record and encrypted payload are permanently deleted from storage and can never be recovered.</p>
            </div>
            <div className="p-2.5 bg-slate-900 border border-slate-800 rounded-lg">
              <strong className="text-blue-400">Q: Why is the secret key in the URL hash fragment (`#`)?</strong>
              <p className="mt-1 text-slate-300">Standard web specifications dictate that text following `#` is never sent over HTTP requests to servers, keeping your decryption key completely client-side.</p>
            </div>
          </div>
        </div>
      )
    }
  ];

  const filteredSections = manualSections.filter((sec) => {
    const matchesTab = activeTab === "all" || sec.category === activeTab;
    const query = searchQuery.toLowerCase();
    const matchesQuery =
      !query ||
      sec.title.toLowerCase().includes(query) ||
      sec.summary.toLowerCase().includes(query);
    return matchesTab && matchesQuery;
  });

  return (
    <div className="fixed inset-0 z-[250] bg-black/80 backdrop-blur-md flex items-center justify-center p-2 sm:p-4 md:p-6 overflow-hidden">
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 20 }}
        className="w-full max-w-4xl h-[92vh] bg-slate-950 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100"
      >
        {/* Header Bar */}
        <div className="p-4 sm:p-5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-blue-500/10 border border-blue-500/20 rounded-xl text-blue-400">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm sm:text-base font-mono font-black tracking-wider text-white">
                  CIPHERVAULT USER MANUAL
                </h2>
                <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-[9px] font-mono uppercase font-bold">
                  PDF READY
                </span>
              </div>
              <p className="text-[10px] sm:text-xs text-slate-400 font-sans">
                Global Operations Manual & Step-by-Step Guidance
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Print Button */}
            <button
              onClick={handlePrint}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition-all hidden sm:flex items-center gap-1 text-xs font-mono"
              title="Print Manual"
            >
              <Printer className="w-4 h-4 text-slate-300" />
            </button>

            {/* PDF Export Button */}
            <button
              onClick={handleDownloadPdf}
              disabled={isGeneratingPdf}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-bold flex items-center gap-2 shadow-lg shadow-blue-500/20 transition-all"
            >
              <Download className="w-4 h-4" />
              <span className="hidden sm:inline">
                {isGeneratingPdf ? "Generating PDF..." : "Export PDF"}
              </span>
              <span className="sm:hidden">PDF</span>
            </button>

            {/* Close Button */}
            <button
              onClick={onClose}
              className="p-2 hover:bg-slate-800 text-slate-400 hover:text-white rounded-lg transition-all ml-1"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Search & Category Filter Bar */}
        <div className="p-3 sm:p-4 bg-slate-900/50 border-b border-slate-800/80 flex flex-col sm:flex-row gap-3 shrink-0">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search manual topics..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl py-2 pl-9 pr-3 text-xs text-white placeholder:text-slate-500 outline-none focus:border-blue-500/50 transition-all font-sans"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0 no-scrollbar">
            {[
              { id: "all", label: "All Topics" },
              { id: "overview", label: "Overview" },
              { id: "sending", label: "Send Files" },
              { id: "receiving", label: "Receive" },
              { id: "chat", label: "Chat" },
              { id: "faq", label: "FAQ" }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold whitespace-nowrap transition-all ${
                  activeTab === tab.id
                    ? "bg-blue-600 text-white shadow-md shadow-blue-500/20"
                    : "bg-slate-900 text-slate-400 hover:bg-slate-800 hover:text-slate-200 border border-slate-800"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Scrollable Printable/PDF Document Area */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6 custom-scrollbar bg-slate-950">
          <div ref={manualContentRef} className="space-y-6 max-w-3xl mx-auto p-2">
            
            {/* Document Cover Header for PDF */}
            <div className="p-6 bg-gradient-to-br from-blue-950/80 via-slate-900 to-slate-950 border border-blue-500/30 rounded-2xl relative overflow-hidden">
              <div className="absolute -right-10 -top-10 w-40 h-40 bg-blue-500/10 rounded-full blur-2xl pointer-events-none" />
              <div className="flex items-center gap-3 mb-3">
                <Shield className="w-8 h-8 text-blue-400" />
                <div>
                  <h1 className="text-xl sm:text-2xl font-mono font-black text-white tracking-wider">
                    CIPHERVAULT USER MANUAL
                  </h1>
                  <p className="text-xs font-mono text-blue-400 uppercase tracking-widest mt-0.5">
                    Zero-Knowledge E2EE File Sharing & Quantum Messenger Protocol
                  </p>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap gap-4 text-[11px] font-mono text-slate-300">
                <div className="flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Version 2.5 • Global Release</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-blue-400" />
                  <span>AES-256-GCM Hardware Encryption</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span>Beginner Friendly Guide</span>
                </div>
              </div>
            </div>

            {/* Quick Start Summary Box */}
            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
              <h3 className="text-xs font-mono font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                <Zap className="w-4 h-4 text-amber-400" />
                <span>Quick Start (3-Step Summary)</span>
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                  <div className="text-blue-400 font-mono font-bold text-xs">01. Select & Lock</div>
                  <p className="text-[11px] text-slate-300 mt-1">
                    Select file, configure expiry time, and click Encrypt.
                  </p>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                  <div className="text-blue-400 font-mono font-bold text-xs">02. Share Link / Key</div>
                  <p className="text-[11px] text-slate-300 mt-1">
                    Send the generated secure link or 15-character key to recipient.
                  </p>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                  <div className="text-blue-400 font-mono font-bold text-xs">03. Unlock & Save</div>
                  <p className="text-[11px] text-slate-300 mt-1">
                    Recipient unlocks content directly inside their browser & downloads.
                  </p>
                </div>
              </div>
            </div>

            {/* Render Filtered Sections */}
            {filteredSections.length === 0 ? (
              <div className="p-8 text-center bg-slate-900/50 border border-slate-800 rounded-xl text-slate-400">
                <HelpCircle className="w-8 h-8 mx-auto mb-2 text-slate-500" />
                <p className="text-xs font-mono">No matching manual sections found.</p>
              </div>
            ) : (
              filteredSections.map((sec) => {
                const IconComponent = sec.icon;
                return (
                  <div
                    key={sec.id}
                    className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition-all"
                  >
                    <div className="flex items-center justify-between gap-3 border-b border-slate-800 pb-3">
                      <div className="flex items-center gap-2.5">
                        <div className="p-2 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400">
                          <IconComponent className="w-4 h-4" />
                        </div>
                        <h3 className="text-sm font-mono font-bold text-white">
                          {sec.title}
                        </h3>
                      </div>

                      <button
                        onClick={() => handleCopy(sec.summary, sec.id)}
                        className="p-1.5 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded text-[10px] font-mono flex items-center gap-1 transition-all"
                        title="Copy Section Summary"
                      >
                        {copiedStep === sec.id ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            <span className="text-emerald-400 font-bold">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy</span>
                          </>
                        )}
                      </button>
                    </div>

                    <p className="text-[11px] text-slate-400 italic">
                      {sec.summary}
                    </p>

                    <div className="pt-1">
                      {sec.content}
                    </div>
                  </div>
                );
              })
            )}

            {/* Document Footer for Print / PDF */}
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl text-center space-y-1 text-[10px] font-mono text-slate-500">
              <p className="uppercase tracking-widest font-bold text-slate-400">
                CipherVault E2EE Security Protocol & Documentation
              </p>
              <p>Generated for User Assistance • Zero-Knowledge Architecture Guaranteed</p>
            </div>

          </div>
        </div>

        {/* Modal Bottom Action Footer */}
        <div className="p-4 bg-slate-900 border-t border-slate-800 flex items-center justify-between gap-3 shrink-0">
          <div className="text-[11px] text-slate-400 font-mono hidden sm:block">
            Need further help? Access live messenger support or review security protocol details.
          </div>
          <div className="flex items-center gap-2 w-full sm:w-auto justify-end">
            <button
              onClick={handleDownloadPdf}
              disabled={isGeneratingPdf}
              className="flex-1 sm:flex-none px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-xl font-mono text-xs font-bold flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20"
            >
              <Download className="w-4 h-4" />
              <span>{isGeneratingPdf ? "Generating PDF..." : "Export Manual PDF"}</span>
            </button>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl font-mono text-xs font-bold"
            >
              Close
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};
