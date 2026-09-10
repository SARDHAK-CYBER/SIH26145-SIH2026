import { useCallback, useRef, useState } from 'react';

interface Props {
  onAnalyze: (file: File) => void;
  onLoadSample: () => void;
  isAnalyzing: boolean;
}

export function UploadPanel({ onAnalyze, onLoadSample, isAnalyzing }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFiles = useCallback((files: FileList | null) => {
    if (files && files[0]) setFile(files[0]);
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* 1-Click Simulated Attack Banner */}
      <div className="glass" style={{
        padding: 22,
        background: 'linear-gradient(135deg, rgba(0, 229, 255, 0.08), rgba(139, 92, 246, 0.08))',
        border: '1px solid rgba(0, 229, 255, 0.3)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <h3 style={{ fontSize: 15, fontWeight: 700, margin: '0 0 4px', color: 'var(--accent-cyan)' }}>
              1-Click Ground Truth Simulated Attack Capture
            </h3>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
              Instantly load simulated attack traffic exercising all 13 engines (DDoS, C2, DGA, JA4, Recon, Exfil, Modbus/DNP3, YARA) and ONNX ML models.
            </p>
          </div>

          <button
            type="button"
            className="btn-primary"
            disabled={isAnalyzing}
            onClick={onLoadSample}
            style={{ padding: '10px 22px', fontSize: 13 }}
          >
            {isAnalyzing ? 'Processing Pipeline…' : 'Load Simulated Attack PCAP'}
          </button>
        </div>
      </div>

      {/* Main Drag-and-Drop Dropzone */}
      <div className="glass" style={{ padding: 0 }}>
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); handleFiles(e.dataTransfer.files); }}
          style={{
            padding: '50px 24px',
            textAlign: 'center',
            borderRadius: 'var(--radius-lg)',
            border: dragging ? '2px dashed var(--accent-cyan)' : '1px dashed var(--glass-border)',
            background: dragging ? 'rgba(0, 229, 255, 0.06)' : 'transparent',
            transition: 'all 0.2s ease',
          }}
        >
          <div style={{
            width: 52,
            height: 52,
            borderRadius: '50%',
            background: 'rgba(0, 229, 255, 0.1)',
            color: 'var(--accent-cyan)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 16px',
          }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
          </div>

          <p style={{ fontSize: 14, color: 'var(--text)', fontWeight: 500, marginBottom: 4 }}>
            Drag & drop raw network packet captures here
          </p>
          <p style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 20 }}>
            Supports standard <span className="mono">.pcap</span> and <span className="mono">.pcapng</span> files up to 200MB
          </p>

          <button
            type="button"
            className="btn-ghost"
            onClick={() => inputRef.current?.click()}
          >
            Browse Local File
          </button>
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng"
            style={{ display: 'none' }}
            onChange={(e) => handleFiles(e.target.files)}
          />

          {file && (
            <div className="glass mono" style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 12,
              color: 'var(--accent-cyan)',
              marginTop: 18,
              padding: '8px 16px',
            }}>
              <span>{file.name}</span>
              <span style={{ color: 'var(--text-dim)' }}>({(file.size / (1024 * 1024)).toFixed(2)} MB)</span>
            </div>
          )}
        </div>

        <div style={{
          padding: '16px 24px',
          background: 'rgba(0,0,0,0.2)',
          borderTop: '1px solid var(--glass-border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
            Primary Parser: <span className="mono" style={{ color: 'var(--accent-cyan)' }}>Zeek + ICSNPP OT</span> • Fallback: <span className="mono" style={{ color: 'var(--accent-teal)' }}>Scapy Pure-Python</span>
          </div>

          <button
            type="button"
            className="btn-primary"
            disabled={!file || isAnalyzing}
            onClick={() => file && onAnalyze(file)}
          >
            {isAnalyzing ? 'Running DPI Engine & ML…' : 'Execute Full Deep Packet Inspection'}
          </button>
        </div>
      </div>
    </div>
  );
}

