import { useState, useEffect, useMemo } from 'react';
import { useIncidents } from '../hooks/useIncidents';
import useSocket from '../hooks/useSocket';
import Card from '../components/UI/Card';
import IncidentTable from '../components/Dashboard/IncidentTable';
import AnomalyChart from '../components/Dashboard/AnomalyChart';
import Badge from '../components/UI/Badge';

const DashboardOverview = () => {
  // 1. Fetch historical incidents via React Query
  const { data: initialIncidents, isLoading, isError } = useIncidents();
  
  // 2. Real-time stream state
  const [liveIncidents, setLiveIncidents] = useState([]);
  
  // 3. Connect to WebSocket
  const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/events';
  const { data: wsEvent, status: wsStatus } = useSocket(wsUrl);

  // 4. Handle incoming real-time events
  useEffect(() => {
    if (wsEvent && wsEvent.type === 'alert') {
      const newAlert = wsEvent.data;
      setLiveIncidents((prev) => {
        // Prevent duplicates
        if (prev.find(a => a.id === newAlert.id)) return prev;
        
        // Map common fields for UI consistency
        const mappedAlert = {
          ...newAlert,
          id: newAlert.id || `LIVE-${Date.now()}`,
          timestamp: newAlert.timestamp || new Date().toISOString(),
          source_ip: newAlert.src_ip,
          dest_ip: newAlert.dst_ip,
          attack_type: newAlert.alert_type,
          status: 'open',
          description: newAlert.raw_payload?.msg || `Alert ${newAlert.alert_type} detected`
        };
        
        return [mappedAlert, ...prev].slice(0, 50); // Keep last 50 live events
      });
    }
  }, [wsEvent]);

  // 5. Merge historical and live data for display
  const allIncidents = useMemo(() => {
    const historical = initialIncidents || [];
    // Combine, filter out duplicates if live ones were already fetched
    const combined = [...liveIncidents, ...historical];
    const unique = Array.from(new Map(combined.map(item => [item.id, item])).values());
    return unique.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }, [initialIncidents, liveIncidents]);

  // Loading / Error States
  if (isLoading && liveIncidents.length === 0) return <div className="h-screen flex items-center justify-center text-silverMuted font-mono animate-pulse">Initializing SOC Tactical View...</div>;

  const highCriticalCount = allIncidents.filter(i => ['HIGH', 'CRITICAL'].includes((i.severity || '').toUpperCase())).length;

  return (
    <div className="space-y-6 animate-slide-in">
      {/* Tactical Stats Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="soc-card p-5 border-l-4 border-l-primary">
          <div className="flex flex-col">
            <span className="text-text-secondary text-xs font-semibold uppercase tracking-wider">Tactical Horizon</span>
            <div className="flex items-baseline space-x-2 mt-1">
              <span className="text-3xl font-bold text-text-main">{allIncidents.length}</span>
              <span className="text-xs text-text-muted">Active Incidents</span>
            </div>
          </div>
        </div>

        <div className={`soc-card p-5 border-l-4 border-l-critical ${highCriticalCount > 0 ? 'animate-pulse-glow' : ''}`}>
          <div className="flex flex-col">
            <span className="text-text-secondary text-xs font-semibold uppercase tracking-wider">Threat Level</span>
            <div className="flex items-baseline space-x-2 mt-1">
              <span className="text-3xl font-bold text-critical">{highCriticalCount}</span>
              <span className="text-xs text-text-muted">High/Critical</span>
            </div>
          </div>
        </div>

        <div className="soc-card p-5 border-l-4 border-l-medium">
          <div className="flex flex-col">
            <span className="text-text-secondary text-xs font-semibold uppercase tracking-wider">Inference Confidence</span>
            <div className="flex items-baseline space-x-2 mt-1">
              <span className="text-3xl font-bold text-text-main">92<span className="text-lg font-normal text-text-muted">%</span></span>
              <span className="text-xs text-text-muted">Avg ML precision</span>
            </div>
          </div>
        </div>

        <div className={`soc-card p-5 border-l-4 ${wsStatus === 'connected' ? 'border-l-low' : 'border-l-critical'}`}>
          <div className="flex flex-col">
            <span className="text-text-secondary text-xs font-semibold uppercase tracking-wider">Stream State</span>
            <div className="mt-2 flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${wsStatus === 'connected' ? 'bg-low animate-pulse' : 'bg-critical'}`} />
              <span className={`text-sm font-mono ${wsStatus === 'connected' ? 'text-low' : 'text-critical'}`}>
                {wsStatus.toUpperCase()}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Main Display Area */}
        <div className="lg:col-span-3 space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="soc-card p-6 lg:col-span-2">
              <h3 className="text-sm font-semibold text-text-secondary uppercase mb-4 tracking-videst">ML Anomaly Detection Vector</h3>
              <div className="h-64">
                <AnomalyChart data={allIncidents} />
              </div>
            </div>

            <div className="soc-card p-6">
              <h3 className="text-sm font-semibold text-text-secondary uppercase mb-4 tracking-videst">High-Risk Targets</h3>
              <div className="space-y-3">
                {allIncidents.slice(0, 5).map((item, i) => (
                  <div key={i} className="flex justify-between items-center p-2 rounded bg-bg-elevated/30 border border-transparent hover:border-border transition-all">
                    <span className="font-mono text-xs text-text-main">{item.source_ip}</span>
                    <Badge variant={item.severity}>{item.severity}</Badge>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="soc-card overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-bg-elevated/10">
              <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-videst">Tactical Event Buffer</h3>
              <div className="flex items-center space-x-2">
                <div className="w-1.5 h-1.5 rounded-full bg-low animate-pulse" />
                <span className="text-[10px] text-text-muted font-mono">REAL-TIME SYNC ACTIVE</span>
              </div>
            </div>
            <IncidentTable incidents={allIncidents} />
          </div>
        </div>

        {/* Sidebar: Digital Pulse (Last 10 Events) */}
        <div className="lg:col-span-1">
          <div className="soc-card flex flex-col h-full max-h-[820px]">
            <div className="px-4 py-3 border-b border-border bg-bg-elevated/20">
              <h3 className="text-xs font-bold text-text-secondary uppercase tracking-tighter">Digital Pulse</h3>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-4 premium-scrollbar">
              {allIncidents.length === 0 ? (
                <div className="h-full flex items-center justify-center text-xs text-text-muted font-mono animate-pulse uppercase">
                  Awaiting Signals...
                </div>
              ) : (
                allIncidents.slice(0, 15).map((evt, idx) => (
                  <div key={evt.id} className="group relative pl-4 border-l border-border hover:border-primary transition-colors">
                    <div className="absolute left-[-4.5px] top-1 w-2 h-2 rounded-full bg-bg-elevated border border-border group-hover:bg-primary transition-colors" />
                    <div className="flex justify-between items-start mb-1">
                      <span className={`text-[10px] font-bold uppercase ${
                        (evt.severity || '').toUpperCase() === 'CRITICAL' ? 'text-critical' : 
                        (evt.severity || '').toUpperCase() === 'HIGH' ? 'text-high' : 'text-text-secondary'
                      }`}>
                        {evt.attack_type}
                      </span>
                      <span className="text-[9px] text-text-muted font-mono">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-xs text-text-main font-medium truncate" title={evt.description}>
                      {evt.description}
                    </div>
                    <div className="text-[10px] text-text-muted font-mono mt-1">
                      {evt.source_ip} <span className="text-border mx-1">/</span> {evt.protocol}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview;
