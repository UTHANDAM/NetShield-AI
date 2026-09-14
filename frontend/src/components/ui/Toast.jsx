'use client';

import { useState, useEffect } from 'react';
import { CheckCircle, AlertTriangle, ShieldAlert, Info, X } from 'lucide-react';

const icons = {
  success: <CheckCircle className="w-5 h-5 text-safe" />,
  error: <ShieldAlert className="w-5 h-5 text-threat" />,
  warning: <AlertTriangle className="w-5 h-5 text-warning" />,
  info: <Info className="w-5 h-5 text-blue-400" />
};

const borders = {
  success: 'border-safe/50',
  error: 'border-threat/50',
  warning: 'border-warning/50',
  info: 'border-blue-400/50'
};

const bgFlags = {
  success: 'bg-safe',
  error: 'bg-threat',
  warning: 'bg-warning',
  info: 'bg-blue-400'
};

export default function Toast({ message, type = 'info', onClose, duration = 3000 }) {
  const [progress, setProgress] = useState(100);
  const [isClosing, setIsClosing] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setProgress((oldProgress) => {
        if (oldProgress <= 0) {
          clearInterval(timer);
          handleClose();
          return 0;
        }
        return oldProgress - (100 / (duration / 50));
      });
    }, 50);

    return () => clearInterval(timer);
  }, [duration]);

  const handleClose = () => {
    setIsClosing(true);
    setTimeout(onClose, 300); // Wait for exit animation
  };

  return (
    <div className={`fixed bottom-4 right-4 w-80 bg-card border ${borders[type]} rounded-lg shadow-2xl shadow-black/80 overflow-hidden transform transition-all duration-300 ${isClosing ? 'translate-y-full opacity-0' : 'translate-y-0 opacity-100'} z-50`}>
      <div className="flex items-start gap-3 p-4">
        <div className="shrink-0 mt-0.5">
          {icons[type]}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-sans text-text-main leading-relaxed">
            {message}
          </p>
        </div>
        <button 
          onClick={handleClose}
          className="shrink-0 p-1 hover:bg-surface rounded text-text-muted hover:text-text-main transition"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
      <div className="h-1 bg-surface w-full">
        <div 
          className={`h-full transition-all duration-75 ease-linear ${bgFlags[type]}`}
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
}
