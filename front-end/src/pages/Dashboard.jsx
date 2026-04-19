import React, { useState, useMemo, useCallback } from 'react';
import { useIncidents } from '../hooks/useIncidents';
import useSocket from '../hooks/useSocket';
import Card from '../components/UI/Card';
import IncidentTable from '../components/Dashboard/IncidentTable';
import AnomalyChart from '../components/Dashboard/AnomalyChart';
import Badge from '../components/UI/Badge';

const DashboardOverview = () => {
  // 1. Fetch historical incidents via React Query
  const { data: initialIncidents, isLoading, isError, error } = useIncidents();
  
  // 2. Real-time stream state
  const [liveIncidents, setLiveIncidents] = useState([]);
  
  // 3. Connect to WebSocket
  const apiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:2345';
  const wsUrl = import.meta.env.VITE_WS_URL || apiBase.replace(/^http/, 'ws') + '/ws/events';
  
  const handleMessage = useCallback((wsEvent) => {
    if (wsEvent && wsEvent.type === 'incident') {
      const newIncident = wsEvent.data;
      setLiveIncidents((prev) => {
        if (prev.find(i => i.id === newIncident.incident_id)) return prev;
        
        const mappedIncident = {
          ...newIncident,
          id: newIncident.incident_id,
          timestamp: newIncident.end_time || new Date().toISOString(),
          source_ip: newIncident.src_ip,
          dest_ip: 'GLOBAL', 
          attack_type: newIncident.incident_type,
          status: 'open',
          description: `${newIncident.incident_type} detected with ${newIncident.confidence} confidence.`,
          severity: newIncident.severity,
          ml_score: newIncident.ml_contributed ? 0.9 : 0.0
        };
        
        return [mappedIncident, ...prev].slice(0, 50);
      });
    }
  }, []);

  const { status: wsStatus } = useSocket(wsUrl, {
    onMessage: handleMessage
  });

  // 5. Merge historical and live data
  const allIncidents = useMemo(() => {
    const historical = initialIncidents || [];
    const combined = [...liveIncidents, ...historical];
    const unique = Array.from(new Map(combined.map(item => [item.id, item])).values());
    return unique.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }, [initialIncidents, liveIncidents]);

  if (isLoading && liveIncidents.length === 0) {
    return (
      <div className="h-screen flex items-center justify-center text-metalsilver-muted font-mono animate-pulse uppercase tracking-[0.3em] font-black">
        Initializing Aegis Tactical View...
      </div>
    );
  }

  if (isError && liveIncidents.length === 0) {
    const errorMessage = error?.userMessage || error?.message || 'Could not reach the backend. Check CORS configuration and server status.';
    return (
      <div className="h-screen flex flex-col items-center justify-center space-y-4 font-mono uppercase tracking-[0.2em]">
        <div className="text-m-critical font-black text-sm">Tactical Feed Unavailable</div>
        <p className="text-[10px] text-metalsilver-muted font-bold max-w-md text-center">
          {errorMessage}
        </p>
      </div>
    );
  }

  const highCriticalCount = allIncidents.filter(i => ['HIGH', 'CRITICAL'].includes((i.severity || '').toUpperCase())).length;

  return (
    <div className="space-y-8 animate-slide-in">
      {/* Tactical Stats Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="border-l-4 border-l-metalgold-main" title="Tactical Horizon" subtitle="ACTIVE SECURITY EVENTS">
          <div className="flex items-baseline space-x-2">
            <span className="text-4xl font-black text-metaltxt-primary">{allIncidents.length}</span>
            <span className="text-[10px] text-metalsilver-muted font-bold uppercase tracking-wider">Signals</span>
          </div>
        </Card>

        <Card 
          className={`border-l-4 border-l-m-critical ${highCriticalCount > 0 ? 'animate-gold-pulse' : ''}`} 
          title="Threat Level" 
          subtitle="HIGH/CRITICAL PRIORITY"
        >
          <div className="flex items-baseline space-x-2">
            <span className="text-4xl font-black text-m-critical">{highCriticalCount}</span>
            <span className="text-[10px] text-metalsilver-muted font-bold uppercase tracking-wider">Vectors</span>
          </div>
        </Card>

        <Card title="Inference Confidence" subtitle="ML PRECISION METRIC">
          <div className="flex items-baseline space-x-2">
            <span className="text-4xl font-black text-metaltxt-primary">92<span className="text-xl font-normal text-metalsilver-muted">%</span></span>
            <span className="text-[10px] text-metalsilver-muted font-bold uppercase tracking-wider">Accuracy</span>
          </div>
        </Card>

        <Card 
          title="Stream State" 
          subtitle="REAL-TIME SYNC STATUS"
          className={`border-l-4 ${wsStatus === 'connected' ? 'border-l-metalgold-main' : 'border-l-m-critical'}`}
        >
          <div className="mt-2 flex items-center space-x-3">
            <div className={`w-3 h-3 rounded-full ${wsStatus === 'connected' ? 'bg-metalgold-main animate-gold-pulse' : 'bg-m-critical'}`} />
            <span className={`text-sm font-black font-mono tracking-widest ${wsStatus === 'connected' ? 'text-metalgold-main' : 'text-m-critical'}`}>
              {wsStatus.toUpperCase()}
            </span>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Main Display Area */}
        <div className="lg:col-span-3 space-y-8">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <Card className="lg:col-span-2" title="ML Anomaly Detection Vector" subtitle="STATISTICAL DEVIATION OVER TIME">
              <div className="h-64">
                <AnomalyChart data={allIncidents} />
              </div>
            </Card>

            <Card title="High-Risk targets" subtitle="TOP THREAT ORIGINS">
              <div className="space-y-3">
                {allIncidents.slice(0, 6).map((item, i) => (
                  <div key={i} className="flex justify-between items-center p-3 rounded-lg bg-metalbg-elevated/30 border border-metal-border group hover:border-metalgold-main/20 transition-all">
                    <span className="font-mono text-xs text-metalsilver-main font-bold">{item.source_ip}</span>
                    <Badge variant={item.severity}>{item.severity}</Badge>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          <Card title="Tactical Event Buffer" subtitle="REAL-TIME COLLATED INTELLIGENCE">
            <div className="-mx-6 -mb-6">
               <IncidentTable incidents={allIncidents} />
            </div>
          </Card>
        </div>

        {/* Sidebar: Digital Pulse (Last 15 Events) */}
        <div className="lg:col-span-1">
          <Card className="h-full max-h-[920px]" title="Digital Pulse" subtitle="LATEST NETWORK SIGNALS">
             <div className="overflow-y-auto pr-4 -mr-4 space-y-6 premium-scrollbar h-[720px]">
              {allIncidents.length === 0 ? (
                <div className="h-full flex items-center justify-center text-[10px] text-metalsilver-muted font-black animate-pulse uppercase tracking-widest">
                  Awaiting Signals...
                </div>
              ) : (
                allIncidents.slice(0, 15).map((evt) => (
                  <div key={evt.id} className="group relative pl-6 border-l border-metal-border hover:border-metalgold-main transition-colors">
                    <div className="absolute left-[-4.5px] top-1.5 w-2 h-2 rounded-full bg-metalbg-secondary border border-metal-border group-hover:bg-metalgold-main transition-colors shadow-[0_0_8px_rgba(0,0,0,1)]" />
                    <div className="flex justify-between items-start mb-1">
                      <span className={`text-[10px] font-black uppercase tracking-tighter ${
                        (evt.severity || '').toUpperCase() === 'CRITICAL' ? 'text-m-critical' : 
                        (evt.severity || '').toUpperCase() === 'HIGH' ? 'text-metalgold-main' : 'text-metalsilver-muted'
                      }`}>
                        {evt.attack_type}
                      </span>
                      <span className="text-[9px] text-metalsilver-muted font-mono font-bold">
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>
                    <div className="text-xs text-metaltxt-primary font-bold truncate tracking-tight" title={evt.description}>
                      {evt.description}
                    </div>
                    <div className="text-[10px] text-metalsilver-muted font-mono mt-1 font-bold">
                      {evt.source_ip} <span className="text-metal-border mx-1">/</span> {evt.protocol || 'UDP'}
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview;
