import React from 'react';
import { AlertCircle } from 'lucide-react';

class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; error: any }> {
  constructor(props: any) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }

  componentDidCatch(error: any, errorInfo: any) {
    console.error("Critical Application Error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#0d0e10] flex flex-col items-center justify-center p-6 text-center">
          <div className="p-4 bg-red-500/10 rounded-full mb-6 border border-red-500/20 shadow-[0_0_30px_rgba(239,68,68,0.1)]">
            <AlertCircle className="w-12 h-12 text-red-500" />
          </div>
          <h1 className="text-xl font-mono font-bold text-white mb-2 uppercase tracking-tighter">System Malfunction</h1>
          <p className="text-xs text-slate-500 max-w-xs mb-8 font-mono leading-relaxed lowercase italic">
            the application encountered a critical runtime error.
          </p>
          <div className="bg-black/40 p-4 border border-white/5 rounded-lg mb-8 max-w-md w-full overflow-hidden">
            <p className="text-[10px] font-mono text-red-400 text-left whitespace-pre-wrap break-all">
              {this.state.error?.message || "Unknown Runtime Error"}
            </p>
          </div>
          <button 
            onClick={() => window.location.reload()}
            className="px-6 py-2 bg-white/5 hover:bg-white/10 text-white rounded font-mono text-xs uppercase tracking-widest transition-all border border-white/10"
          >
            Reboot Interface
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
