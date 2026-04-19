import React, { useState, useMemo } from 'react';
import { useIncidents } from '../hooks/useIncidents';
import { ShieldCheck, Search, Filter, Activity, Clock, Zap, AlertCircle, ChevronRight, Fingerprint } from 'lucide-react';
import Badge from '../components/UI/Badge';
import Card from '../components/UI/Card';

const IncidentsPage = () => {
  const { data: incidents, isLoading, isError, error } = useIncidents();
  const [filter, setFilter] = useState('ALL');
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);

  const filteredIncidents = useMemo(() => {
    if (!incidents) return [];
    if (filter === 'ALL') return incidents;
    return incidents.filter(i => (i.severity || '').toUpperCase() === filter);
  }, [incidents, filter]);

  const selectedIncident = useMemo(() => {
    return incidents?.find(i => i.id === selectedIncidentId);
  }, [incidents, selectedIncidentId]);

  if (isLoading) {
    return (
      <div className="h-full flex items-center justify-center text-metalsilver-muted font-mono animate-pulse uppercase tracking-widest font-black">
        <Activity className="text-metalgold-main mr-4" size={24} />
        Syncing Integrated Event Bus...
      </div>
    );
  }

  if (isError) {
    const errorMessage = error?.message || 'Backend unreachable or returned an error.';
    return (
      <div className="h-full flex flex-col items-center justify-center space-y-4 font-mono uppercase tracking-[0.2em]">
        <AlertCircle className="text-m-critical" size={48} />
        <span className="text-m-critical font-black text-sm">Incident Feed Unavailable</span>
        <p className="text-[10px] text-metalsilver-muted font-bold text-center max-w-md">{errorMessage}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-700">
      {/* Page Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center space-x-4">
          <div className="w-12 h-12 rounded-xl bg-metalgold-main/10 border border-metalgold-main/20 flex items-center justify-center">
            <ShieldCheck className="text-metalgold-main" size={24} />
          </div>
          <div>
            <h1 className="text-2xl font-black text-metaltxt-primary tracking-widest uppercase">Incident Response</h1>
            <p className="text-metalsilver-muted text-[10px] font-bold uppercase tracking-widest mt-1">Managed security incidents and correlated telemetry.</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
        {/* Incident List */}
        <div className="lg:col-span-1 space-y-4 max-h-[calc(100vh-250px)] overflow-y-auto pr-2 premium-scrollbar">
          <div className="flex items-center space-x-2 mb-4 bg-metalbg-secondary/50 p-1.5 rounded-xl border border-metal-border w-fit">
            {['ALL', 'CRITICAL', 'HIGH'].map(lvl => (
              <button 
                key={lvl}
                onClick={() => setFilter(lvl)}
                className={`px-3 py-1.5 rounded-lg text-[9px] font-black tracking-widest transition-all uppercase ${
                  filter === lvl 
                    ? 'bg-metalgold-main text-metalbg-main shadow-lg shadow-metalgold-main/20' 
                    : 'bg-transparent text-metalsilver-muted hover:text-metaltxt-primary'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>

          {filteredIncidents.length > 0 ? filteredIncidents.map((incident) => (
            <div 
              key={incident.id}
              onClick={() => setSelectedIncidentId(incident.id)}
              className={`soc-card p-4 cursor-pointer transition-all group ${
                selectedIncidentId === incident.id 
                  ? 'border-metalgold-main bg-metalgold-main/5 shadow-lg shadow-metalgold-main/5 saturate-[1.2]' 
                  : 'hover:border-metalgold-main/30'
              }`}
            >
              <div className="flex justify-between items-start mb-3">
                <Badge variant={incident.severity?.toLowerCase() || 'medium'}>
                  {incident.severity || 'UNKNOWN'}
                </Badge>
                <span className="text-[9px] font-mono font-black text-metalsilver-muted uppercase tracking-tighter">
                  {new Date(incident.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
              <h4 className="text-[11px] font-black text-metaltxt-primary uppercase tracking-tight mb-2 group-hover:text-metalgold-main transition-colors leading-tight">
                {incident.title || 'Security Intrusion Detected'}
              </h4>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                   <div className="w-1.5 h-1.5 rounded-full bg-metalgold-main animate-pulse" />
                   <span className="text-[9px] font-mono font-black text-metalsilver-muted uppercase">{incident.id.split('-')[0]}</span>
                </div>
                <ChevronRight size={14} className={`text-metalsilver-muted transition-transform ${selectedIncidentId === incident.id ? 'translate-x-1 text-metalgold-main' : ''}`} />
              </div>
            </div>
          )) : (
            <div className="text-center py-20 opacity-30">
               <ShieldCheck className="mx-auto mb-4" size={40} />
               <p className="text-[10px] font-black uppercase tracking-widest">No Active Incidents</p>
            </div>
          )}
        </div>

        {/* Incident Detail */}
        <div className="lg:col-span-2 space-y-6">
          {selectedIncident ? (
            <div className="animate-in slide-in-from-right duration-500 space-y-6">
               <Card title="Incident Dossier" subtitle={`#${selectedIncident.id}`}>
                  <div className="space-y-8 p-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-4">
                        <div className="flex items-center space-x-3">
                           <div className="p-3 rounded-xl bg-metalbg-elevated border border-metal-border">
                              <Fingerprint className="text-metalgold-main" size={24} />
                           </div>
                           <div>
                              <h3 className="text-lg font-black text-metaltxt-primary uppercase tracking-tight">{selectedIncident.title}</h3>
                              <p className="text-[10px] text-metalsilver-muted font-bold uppercase tracking-widest">{selectedIncident.type || 'Anomalous Activity'}</p>
                           </div>
                        </div>
                        <div className="flex items-center space-x-6">
                           <div className="flex flex-col">
                              <span className="text-[9px] font-black text-metalsilver-muted uppercase tracking-widest">Status</span>
                              <span className="text-xs font-black text-metalgold-main uppercase italic">{selectedIncident.status || 'INVESTIGATING'}</span>
                           </div>
                           <div className="flex flex-col">
                              <span className="text-[9px] font-black text-metalsilver-muted uppercase tracking-widest">Severity score</span>
                              <span className="text-xs font-black text-m-critical uppercase">9.8/10</span>
                           </div>
                           <div className="flex flex-col">
                              <span className="text-[9px] font-black text-metalsilver-muted uppercase tracking-widest">First seen</span>
                              <span className="text-xs font-black text-metalsilver-main uppercase">{new Date(selectedIncident.timestamp).toLocaleString()}</span>
                           </div>
                        </div>
                      </div>
                      <button className="px-6 py-2.5 rounded-xl bg-m-critical text-metalbg-main font-black text-[10px] uppercase tracking-[0.2em] shadow-lg shadow-m-critical/20 hover:scale-[1.02] active:scale-[0.98] transition-all">
                        Contain Threat
                      </button>
                    </div>

                    <div className="p-6 rounded-2xl bg-[#0E0E10] border border-metal-border space-y-4 relative overflow-hidden">
                       <div className="absolute top-0 right-0 p-4 opacity-5">
                          <Zap size={80} className="text-metalgold-main" />
                       </div>
                       <h4 className="text-[10px] font-black text-metalsilver-main uppercase tracking-[0.3em] flex items-center space-x-2">
                         <Activity size={14} className="text-metalgold-main" />
                         <span>Tactical Summary</span>
                       </h4>
                       <p className="text-xs text-metalsilver-muted font-bold leading-relaxed relative z-10">
                         {selectedIncident.description || "The detection system identified a statistically significant deviation in network traffic patterns. Initial heuristics suggest a possible lateral movement attempt or data exfiltration baseline. Correlated with 12 distinct alert signals in the past 180 seconds."}
                       </p>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                       <div className="soc-card p-4 space-y-2">
                          <span className="text-[9px] font-black text-metalsilver-muted uppercase">Source Intelligence</span>
                          <div className="font-mono text-sm text-metaltxt-primary font-black">{selectedIncident.src_ip || '192.168.1.100'}</div>
                          <div className="text-[9px] text-metalgold-main font-black uppercase tracking-widest">Risk Score: 85%</div>
                       </div>
                       <div className="soc-card p-4 space-y-2">
                          <span className="text-[9px] font-black text-metalsilver-muted uppercase">Affected Asset</span>
                          <div className="font-mono text-sm text-metaltxt-primary font-black">PROD-DB-01</div>
                          <div className="text-[9px] text-green-500 font-black uppercase tracking-widest">Protected</div>
                       </div>
                    </div>
                  </div>
               </Card>

               <div className="soc-card p-6 bg-gradient-to-r from-metalbg-secondary to-metalbg-main border-l-4 border-l-metalgold-main animate-pulse">
                  <div className="flex items-center space-x-4">
                     <div className="w-10 h-10 rounded-full bg-metalgold-main/10 flex items-center justify-center text-metalgold-main">
                        <AlertCircle size={20} />
                     </div>
                     <div className="flex-1">
                        <h4 className="text-[10px] font-black text-metaltxt-primary uppercase tracking-widest">SOC Recommendation</h4>
                        <p className="text-[11px] text-metalsilver-muted font-bold mt-1 uppercase tracking-tight italic">Initiate firewall rule base update and isolate source VLAN immediately.</p>
                     </div>
                  </div>
               </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center space-y-6 soc-card p-12 border-dashed opacity-50">
               <div className="w-20 h-20 rounded-full bg-metalbg-elevated border border-metal-border flex items-center justify-center">
                  <Clock size={32} className="text-metalsilver-muted" />
               </div>
               <div className="text-center">
                 <h3 className="text-sm font-black text-metaltxt-primary uppercase tracking-[0.3em]">Awaiting Selection</h3>
                 <p className="text-[10px] text-metalsilver-muted font-bold uppercase mt-2 tracking-widest">Select an incident from the operational queue to view telemetry.</p>
               </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default IncidentsPage;
