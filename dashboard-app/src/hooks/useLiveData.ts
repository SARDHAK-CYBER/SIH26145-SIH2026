import { useCallback, useEffect, useRef, useState } from 'react';
import { live } from '../api/client';
import type {
  Alert, AlertSummary, CaptureStatus, FlowRow, HostRow, LiveTab, ProtoRow, SeriesPoint,
} from '../types/alert';

export interface LiveData {
  status: CaptureStatus;
  series: SeriesPoint[];
  summary: AlertSummary;
  hosts: HostRow[];
  protocols: ProtoRow[];
  flows: FlowRow[];
  alerts: Alert[];
  reachable: boolean;
  refreshStatus: () => void;
  resetAlerts: () => void;
}

const EMPTY_SUMMARY: AlertSummary = { alerts_by_class: {}, alerts_by_severity: {} };

/** Everything the live dashboard shows, polled at rates matched to how fast each thing changes. */
export function useLiveData(tab: LiveTab): LiveData {
  const [status, setStatus] = useState<CaptureStatus>({ running: false });
  const [reachable, setReachable] = useState(true);
  const [series, setSeries] = useState<SeriesPoint[]>([]);
  const [summary, setSummary] = useState<AlertSummary>(EMPTY_SUMMARY);
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [protocols, setProtocols] = useState<ProtoRow[]>([]);
  const [flows, setFlows] = useState<FlowRow[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const seen = useRef<Set<string>>(new Set());
  const esRef = useRef<EventSource | null>(null);
  const hasAgent = status.running || status.finished || (status.capture?.recv ?? 0) > 0;

  const refreshStatus = useCallback(() => {
    live.status().then((s) => { setStatus(s); setReachable(true); }).catch(() => setReachable(false));
  }, []);

  const resetAlerts = useCallback(() => { seen.current = new Set(); setAlerts([]); }, []);

  useEffect(() => {
    refreshStatus();
    const t = window.setInterval(refreshStatus, 1000);
    return () => window.clearInterval(t);
  }, [refreshStatus]);

  // charts / protocol mix / alert summary
  useEffect(() => {
    if (!hasAgent) return;
    const pull = () => {
      live.series(600).then(setSeries).catch(() => {});
      live.summary().then(setSummary).catch(() => {});
      live.protocols().then(setProtocols).catch(() => {});
    };
    pull();
    const t = window.setInterval(pull, 2000);
    return () => window.clearInterval(t);
  }, [hasAgent]);

  useEffect(() => {
    if (!hasAgent || (tab !== 'overview' && tab !== 'hosts')) return;
    const pull = () => live.hosts(tab === 'hosts' ? 1000 : 60).then(setHosts).catch(() => {});
    pull();
    const t = window.setInterval(pull, 3000);
    return () => window.clearInterval(t);
  }, [hasAgent, tab]);

  useEffect(() => {
    if (!hasAgent || tab !== 'flows') return;
    const pull = () => live.flows(100).then(setFlows).catch(() => {});
    pull();
    const t = window.setInterval(pull, 2500);
    return () => window.clearInterval(t);
  }, [hasAgent, tab]);

  // alert backlog (also for a finished replay, whose stream has closed), then live SSE
  useEffect(() => {
    if (!hasAgent) return;
    live.alerts(300).then((rows) => {
      const fresh = rows.filter((a) => !seen.current.has(a.alert_id));
      fresh.forEach((a) => seen.current.add(a.alert_id));
      if (fresh.length) setAlerts((prev) => [...fresh.reverse(), ...prev].slice(0, 500));
    }).catch(() => {});
  }, [hasAgent, status.finished]);

  useEffect(() => {
    esRef.current?.close();
    esRef.current = null;
    if (!status.running) return;
    const es = new EventSource(live.streamUrl());
    es.onmessage = (ev) => {
      if (!ev.data) return;
      try {
        const a: Alert = JSON.parse(ev.data);
        if (seen.current.has(a.alert_id)) return;
        seen.current.add(a.alert_id);
        setAlerts((prev) => [a, ...prev].slice(0, 500));
      } catch { /* keep-alive comment */ }
    };
    esRef.current = es;
    return () => { es.close(); };
  }, [status.running]);

  return { status, series, summary, hosts, protocols, flows, alerts, reachable, refreshStatus, resetAlerts };
}
