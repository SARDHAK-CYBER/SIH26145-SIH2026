export type Mode = 'upload' | 'live';

interface Props {
  mode: Mode;
  onSelect: (mode: Mode) => void;
}

export function ModeSelector({ mode, onSelect }: Props) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 32 }}>
      <div
        className={`glass glass-interactive ${mode === 'upload' ? 'glass-active' : ''}`}
        style={{ padding: 22 }}
        onClick={() => onSelect('upload')}
      >
        <div className="mono" style={{ color: 'var(--accent-teal)', fontSize: 12, marginBottom: 10 }}>01</div>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 6 }}>Upload PCAP File</h2>
        <p style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.5 }}>
          Submit a captured or replayed .pcap file for full offline analysis across every detection engine.
        </p>
        <div className="mono" style={{ fontSize: 11, color: 'var(--accent-teal)', marginTop: 14 }}>● ACTIVE</div>
      </div>

      <div
        className="glass glass-disabled"
        style={{ padding: 22 }}
        onClick={() => onSelect('live')}
        title="Not available yet"
      >
        <div className="mono" style={{ color: 'var(--text-faint)', fontSize: 12, marginBottom: 10 }}>02</div>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 6 }}>Live Capture Analysis</h2>
        <p style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.5 }}>
          Select a network interface and analyze traffic as it arrives, in real time.
        </p>
        <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 14 }}>○ NOT YET AVAILABLE</div>
      </div>
    </div>
  );
}
