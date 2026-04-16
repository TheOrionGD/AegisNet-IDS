import React, { useState, useMemo } from 'react';
import { useAlerts } from '../hooks/useAlerts';
import { ShieldAlert, Search, Filter, AlertTriangle, Clock, Server, Monitor } from 'lucide-react';
import Badge from '../components/UI/Badge';

const AlertsPage = () => {
  const { data: alerts, isLoading } = useAlerts();
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const filteredAlerts = useMemo(() => {
    if (!alerts) return [];
    return alerts.filter(alert => {
      const matchSearch = (alert.message || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
                          (alert.src_ip || '').toLowerCase().includes(searchTerm.toLowerCase());
      const matchSeverity = filterSeverity === 'ALL' || (alert.severity || '').toUpperCase() === filterSeverity;
      return matchSearch && matchSeverity;
    });
  }, [alerts, searchTerm, filterSeverity]);

  if (isLoading) {
    return (
      <div className="h-full flex flex-col items-center justify-center space-y-4 text-metalsilver-muted font-mono animate-pulse uppercase tracking-[0.3em] font-black">
        <Server className="text-metalgold-main animate-bounce" size={48} />
        <span>Syncing Tactical Alert Buffer...</span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-700">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="flex items-center space-x-4">
          <div className="w-14 h-14 rounded-2xl bg-metalgold-main/10 border border-metalgold-main/20 flex items-center justify-center shadow-lg shadow-metalgold-main/5">
            <ShieldAlert className="text-metalgold-main" size={28} />
          </div>
          <div>
            <h1 className="text-3xl font-black text-metaltxt-primary tracking-widest uppercase">Tactical Alerts</h1>
            <p className="text-metalsilver-muted text-[10px] font-bold uppercase tracking-widest mt-1">Real-time threat detection and anomaly stream.</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-3">
           <div className="px-4 py-2 rounded-xl bg-metalbg-secondary/50 border border-metal-border flex items-center space-x-2">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-[10px] font-mono font-black text-metalsilver-main uppercase tracking-widest">Link Active</span>
           </div>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="soc-card p-4 flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="relative w-full md:w-96 group">
          <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none text-metalsilver-muted group-focus-within:text-metalgold-main transition-colors">
            <Search size={18} />
          </div>
          <input 
            type="text"
            placeholder="SEARCH THREATS (IP, MESSAGE, VECTOR)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-metalbg-main/50 border border-metal-border rounded-xl py-3 pl-12 pr-4 text-[11px] font-bold text-metaltxt-primary placeholder:text-metalsilver-muted/30 focus:outline-none focus:border-metalgold-main transition-all"
          />
        </div>

        <div className="flex items-center space-x-2 overflow-x-auto w-full md:w-auto pb-1 md:pb-0">
          <Filter size={16} className="text-metalsilver-muted mr-2 hidden md:block" />
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(lvl => (
            <button 
              key={lvl}
              onClick={() => setFilterSeverity(lvl)}
              className={`px-4 py-2 rounded-lg text-[9px] font-black tracking-widest transition-all uppercase whitespace-nowrap ${
                filterSeverity === lvl 
                  ? 'bg-metalgold-main text-metalbg-main shadow-lg shadow-metalgold-main/20' 
                  : 'bg-metalbg-elevated/50 text-metalsilver-muted hover:text-metaltxt-primary hover:bg-metalbg-elevated'
              }`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Alerts Table */}
      <div className="soc-card overflow-hidden">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-metal-border text-[10px] font-black text-metalsilver-muted uppercase tracking-[0.2em] bg-metalbg-secondary/30">
              <th className="px-6 py-5">Timestamp</th>
              <th className="px-6 py-5">Severity</th>
              <th className="px-6 py-5">Source Vector</th>
              <th className="px-6 py-5">Description</th>
              <th className="px-6 py-5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-metal-border/50">
            {filteredAlerts.length > 0 ? filteredAlerts.map((alert, idx) => (
              <tr key={idx} className="hover:bg-[#1C1D20] group transition-colors">
                <td className="px-6 py-5">
                  <div className="flex items-center space-x-2">
                    <Clock size={14} className="text-metalsilver-muted" />
                    <span className="font-mono text-[11px] font-bold text-metalsilver-main">
                      {new Date(alert.timestamp).toLocaleTimeString([], { hour12: false })}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-5">
                  <Badge variant={alert.severity?.toLowerCase() || 'medium'}>
                    {alert.severity || 'UNKNOWN'}
                  </Badge>
                </td>
                <td className="px-6 py-5">
                  <div className="flex flex-col">
                    <span className="font-mono text-xs text-metaltxt-primary font-black tracking-tight group-hover:text-metalgold-main transition-colors">{alert.src_ip}</span>
                    <span className="text-[9px] text-metalsilver-muted font-bold uppercase tracking-tighter">Attribution: {alert.metadata?.country || 'Global'}</span>
                  </div>
                </td>
                <td className="px-6 py-5">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 rounded-lg bg-metalbg-elevated border border-metal-border flex items-center justify-center shrink-0">
                      <AlertTriangle size={14} className={
                        alert.severity === 'CRITICAL' ? 'text-m-critical' : 
                        alert.severity === 'HIGH' ? 'text-m-high' : 'text-metalgold-main'
                      } />
                    </div>
                    <span className="text-[11px] text-metalsilver-main font-bold leading-relaxed">{alert.message}</span>
                  </div>
                </td>
                <td className="px-6 py-5 text-right">
                   <button className="px-4 py-1.5 rounded-lg border border-metal-border text-[9px] font-black uppercase tracking-widest text-metalsilver-muted hover:text-metalgold-main hover:border-metalgold-main transition-all group-hover:bg-metalgold-main/5">
                     Details
                   </button>
                </td>
              </tr>
            )) : (
              <tr>
                <td colSpan="5" className="px-6 py-20 text-center">
                   <Monitor className="mx-auto text-metalsilver-muted/20 mb-4" size={48} />
                   <p className="text-[11px] font-black text-metalsilver-muted uppercase tracking-[0.4em]">Zero Active Threats Detected in Buffer</p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination / Summary Footer */}
      <div className="flex items-center justify-between text-[10px] font-black text-metalsilver-muted uppercase tracking-widest px-2">
        <span>Showing {filteredAlerts.length} of {alerts?.length || 0} Critical Signals</span>
        <div className="flex space-x-2">
          <button className="px-3 py-1.5 rounded bg-metalbg-secondary border border-metal-border opacity-50 cursor-not-allowed">Previous</button>
          <button className="px-3 py-1.5 rounded bg-metalbg-secondary border border-metal-border hover:text-metaltxt-primary transition-colors">Next</button>
        </div>
      </div>
    </div>
  );
};

export default AlertsPage;
