import React, { useState, useMemo } from 'react';
import { useIncidents } from '../hooks/useIncidents';
import { useAnomalies } from '../hooks/useAnomalies';
import { useTopIPs } from '../hooks/useTopIPs';
import { useTimeline } from '../hooks/useTimeline';
import IncidentTable from '../components/Dashboard/IncidentTable';
import Card from '../components/UI/Card';
import Badge from '../components/UI/Badge';
import { 
  ShieldAlert, 
  Activity, 
  Globe, 
  Clock, 
  Zap, 
  Search, 
  Filter,
  ArrowUpRight,
  Fingerprint,
  ShieldCheck,
  AlertTriangle,
  History,
  Crosshair
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell
} from 'recharts';

// --- Components ---

const PageHeader = ({ title, icon, description }) => {
  const IconComponent = icon;
  return (
    <div className="flex items-center justify-between mb-8 animate-in slide-in-from-top duration-500">
      <div className="flex items-center space-x-4">
        <div className="w-12 h-12 rounded-xl bg-metalgold-main/10 border border-metalgold-main/20 flex items-center justify-center shadow-lg shadow-metalgold-main/5">
          {IconComponent && <IconComponent className="text-metalgold-main" size={24} />}
        </div>
        <div>
          <h1 className="text-2xl font-black text-metaltxt-primary tracking-widest uppercase">{title}</h1>
          <p className="text-metalsilver-muted text-[10px] font-bold uppercase tracking-widest mt-1">{description}</p>
        </div>
      </div>
      <div className="flex items-center space-x-2">
         <span className="text-[9px] font-mono font-black text-metalgold-main px-3 py-1 rounded-lg bg-metalgold-main/10 border border-metalgold-main/20 uppercase tracking-widest shadow-inner">Live Tactical Link</span>
      </div>
    </div>
  );
};

// --- Page Implementations ---

export const IncidentsPage = () => {
  const { data: incidents, isLoading } = useIncidents();
  const [filter, setFilter] = useState('ALL');

  const filteredIncidents = useMemo(() => {
    if (!incidents) return [];
    if (filter === 'ALL') return incidents;
    return incidents.filter(i => (i.severity || '').toUpperCase() === filter);
  }, [incidents, filter]);

  if (isLoading) return <div className="h-full flex items-center justify-center text-metalsilver-muted font-mono animate-pulse uppercase tracking-widest font-black">Syncing Tactical Incident Buffer...</div>;

  return (
    <div className="space-y-6">
      <PageHeader 
        title="Incident Management" 
        icon={ShieldAlert} 
        description="Correlated security incidents requiring investigation and response."
      />
      
      <div className="flex items-center space-x-3 mb-6 bg-metalbg-secondary/50 p-2 rounded-xl border border-metal-border w-fit">
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(lvl => (
          <button 
            key={lvl}
            onClick={() => setFilter(lvl)}
            className={`px-4 py-2 rounded-lg text-[10px] font-black tracking-widest transition-all uppercase ${
              filter === lvl 
                ? 'bg-metalgold-main text-metalbg-main shadow-lg shadow-metalgold-main/20' 
                : 'bg-transparent text-metalsilver-muted hover:text-metalsilver-main hover:bg-metalbg-elevated'
            }`}
          >
            {lvl}
          </button>
        ))}
      </div>

      <div className="animate-in fade-in slide-in-from-bottom duration-700">
        <IncidentTable incidents={filteredIncidents} />
      </div>
    </div>
  );
};

export const AnomaliesPage = () => {
  const { data: anomalies, isLoading } = useAnomalies();

  if (isLoading) return <div className="h-full flex items-center justify-center text-metalsilver-muted font-mono animate-pulse uppercase tracking-widest font-black">Running ML Inference Pipeline...</div>;

  return (
    <div className="space-y-6">
      <PageHeader 
        title="ML Anomalies View" 
        icon={Activity} 
        description="Statistically significant deviations detected by ML models."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {anomalies?.map((anomaly, idx) => (
          <div key={idx} className="soc-card p-6 space-y-4 hover:border-metalgold-main/50 transition-all group animate-in zoom-in-95 duration-500" style={{ animationDelay: `${idx * 50}ms` }}>
            <div className="flex justify-between items-start">
              <div className="p-3 rounded-xl bg-metalbg-elevated border border-metal-border group-hover:bg-metalgold-main/10 group-hover:border-metalgold-main/20 transition-colors">
                <Fingerprint className="text-metalgold-main" size={20} />
              </div>
              <div className="text-right">
                <div className="text-[9px] font-black text-metalsilver-muted uppercase tracking-[0.2em]">{anomaly.model_type}</div>
                <div className="text-xl font-black text-metalgold-main tracking-tighter">{(anomaly.anomaly_score * 100).toFixed(1)}%</div>
              </div>
            </div>
            
            <div>
              <h4 className="text-xs font-black text-metaltxt-primary uppercase tracking-widest mb-1">Anomaly Pulse Detected</h4>
              <p className="text-[11px] text-metalsilver-muted leading-relaxed font-bold">{anomaly.message}</p>
            </div>

            <div className="pt-4 border-t border-metal-border flex justify-between items-center text-[9px] font-mono font-black text-metalsilver-muted uppercase tracking-tighter">
              <span className="text-metalgold-main/60">{anomaly.src_ip}</span>
              <span>{new Date(anomaly.timestamp).toLocaleTimeString()}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export const IPsPage = () => {
  const { data: topIps, isLoading } = useTopIPs();

  if (isLoading) return <div className="h-full flex items-center justify-center text-metalsilver-muted font-mono animate-pulse uppercase tracking-widest font-black">Aggregating Global Threat Intelligence...</div>;

  return (
    <div className="space-y-6">
      <PageHeader 
        title="IP Intelligence" 
        icon={Globe} 
        description="Identified high-risk source vectors and geographical attribution."
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 soc-card overflow-hidden">
          <div className="px-6 py-4 border-b border-metal-border bg-[#222326]">
             <h3 className="text-xs font-black text-metalsilver-main uppercase tracking-[0.2em]">Ranked Attack Vectors</h3>
          </div>
          <div className="p-0">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-metal-border text-[9px] font-black text-metalsilver-muted uppercase tracking-widest bg-metalbg-secondary/50">
                  <th className="px-6 py-4">IP Address</th>
                  <th className="px-6 py-4 text-center">Threat Score</th>
                  <th className="px-6 py-4">Occurrences</th>
                  <th className="px-6 py-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {topIps?.map((ip, idx) => (
                  <tr key={idx} className="border-b border-metal-border/50 hover:bg-[#2A2B2F] transition-colors group">
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-3">
                        <div className="w-1.5 h-1.5 rounded-full bg-metalgold-main animate-gold-pulse"></div>
                        <span className="font-mono text-xs text-metaltxt-primary font-bold group-hover:text-metalgold-main transition-colors">{ip.src_ip}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-center">
                       <Badge variant={(ip.alert_count || 0) > 1000 ? 'critical' : 'high'}>
                         {(ip.alert_count || 0) > 1000 ? 'CRITICAL' : 'HIGH'}
                       </Badge>
                    </td>
                    <td className="px-6 py-4 font-mono text-[10px] text-metalsilver-muted font-bold uppercase tracking-tighter">{(ip.alert_count || 0).toLocaleString()} signals</td>
                    <td className="px-6 py-4 text-right">
                      <button className="p-2 rounded-lg bg-metalbg-elevated/50 text-metalsilver-muted hover:text-metalgold-main hover:bg-metalgold-main/10 transition-all">
                        <ArrowUpRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="soc-card p-6 space-y-8 bg-gradient-to-br from-metalbg-secondary to-metalbg-main">
          <h3 className="text-xs font-black text-metalsilver-main uppercase tracking-[0.2em]">Attribution Insights</h3>
          <div className="space-y-6">
            <div className="p-4 rounded-xl bg-metalbg-elevated/30 border border-metal-border space-y-3">
               <div className="flex justify-between items-center text-[10px] font-black uppercase tracking-widest">
                 <span className="text-metalsilver-muted">Primary Protocol</span>
                 <span className="text-metalgold-main italic">TCP/443</span>
               </div>
               <div className="w-full bg-metalbg-main h-1.5 rounded-full overflow-hidden border border-metal-border/50">
                 <div className="bg-metalgold-main h-full w-[78%] shadow-[0_0_8px_var(--gold-main)]"></div>
               </div>
            </div>
            <div className="p-4 rounded-xl bg-metalbg-elevated/30 border border-metal-border space-y-3">
               <div className="flex justify-between items-center text-[10px] font-black uppercase tracking-widest">
                 <span className="text-metalsilver-muted">Botnet Signatures</span>
                 <span className="text-m-critical">Mirai (Detected)</span>
               </div>
               <div className="w-full bg-metalbg-main h-1.5 rounded-full overflow-hidden border border-metal-border/50">
                 <div className="bg-m-critical h-full w-[12%] shadow-[0_0_8px_var(--critical)]"></div>
               </div>
            </div>
          </div>
          
          <div className="mt-8 text-center p-8 border-2 border-dashed border-metal-border rounded-2xl bg-metalbg-main/20">
             <Globe className="mx-auto text-metalsilver-muted mb-3 opacity-30" size={40} />
             <p className="text-[9px] text-metalsilver-muted font-black uppercase tracking-[0.3em]">Global Heatmap Offline</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export const TimelinePage = () => {
  const { data: timeline, isLoading } = useTimeline();

  const chartData = useMemo(() => {
    if (!timeline || !Array.isArray(timeline)) return [];
    return timeline.map(item => ({
      time: item.time_bucket,
      count: item.volume
    }));
  }, [timeline]);

  if (isLoading) return <div className="h-full flex items-center justify-center text-metalsilver-muted font-mono animate-pulse uppercase tracking-widest font-black">Reconstructing Log Packets...</div>;

  return (
    <div className="space-y-8">
      <PageHeader 
        title="Attack Timeline" 
        icon={Clock} 
        description="Temporal distribution of network anomalies and correlated incidents."
      />

      <div className="soc-card p-6 h-96">
        <h3 className="text-xs font-black text-metalsilver-main uppercase mb-6 tracking-[0.2em]">24-Hour Event Density</h3>
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#D4AF37" stopOpacity={0.6}/>
                <stop offset="95%" stopColor="#D4AF37" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#222326" vertical={false} />
            <XAxis 
              dataKey="time" 
              tick={{fill: '#8F8F8F', fontSize: 9, fontWeight: 'bold'}} 
              stroke="#222326"
              tickFormatter={(t) => t.split(' ')[1]}
            />
            <YAxis tick={{fill: '#8F8F8F', fontSize: 9, fontWeight: 'bold'}} stroke="#222326" />
            <Tooltip 
              contentStyle={{backgroundColor: '#1A1A1D', border: '1px solid rgba(212, 175, 55, 0.2)', borderRadius: '8px', fontSize: '10px', color: '#F5F5F5', textTransform: 'uppercase', fontWeight: 'bold'}}
              itemStyle={{color: '#D4AF37'}}
            />
            <Area type="monotone" dataKey="count" stroke="#D4AF37" fillOpacity={1} fill="url(#colorCount)" strokeWidth={3} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      
      <div className="soc-card p-6">
         <h3 className="text-xs font-black text-metalsilver-main uppercase mb-8 tracking-[0.2em]">Tactical Milestone Stream</h3>
         <div className="space-y-10 relative before:absolute before:inset-y-0 before:left-[11px] before:w-0.5 before:bg-metal-border/30">
            {chartData.slice(-6).reverse().map((d, i) => (
              <div key={i} className="relative pl-12 group">
                <div className="absolute left-[-1.5px] top-1.5 w-7 h-7 rounded-full bg-metalbg-secondary border-2 border-metal-border group-hover:border-metalgold-main flex items-center justify-center z-10 transition-colors shadow-2xl">
                  <Zap size={12} className="text-metalsilver-muted group-hover:text-metalgold-main" />
                </div>
                <div className="flex flex-col">
                  <span className="text-[10px] font-mono font-black text-metalgold-main/60 uppercase tracking-widest mb-1">{d.time}</span>
                  <span className="text-sm font-black text-metaltxt-primary uppercase tracking-tight">Signal Burst Identified</span>
                  <p className="text-[11px] text-metalsilver-muted font-bold mt-1">Detected <span className="text-metalsilver-main font-black">{d.count}</span> security events during this operational window.</p>
                </div>
              </div>
            ))}
         </div>
      </div>
    </div>
  );
};

export const Phase4Page = () => {
  const [logs, setLogs] = useState([
    { ts: new Date().toLocaleTimeString(), msg: "SYSTEM: Awaiting next intrusion cycle..." }
  ]);
  const [isExecuting, setIsExecuting] = useState(false);

  const addLog = (msg) => {
    setLogs(prev => [{ ts: new Date().toLocaleTimeString(), msg }, ...prev].slice(0, 15));
  };

  const handleAction = (action) => {
    setIsExecuting(true);
    addLog(`SOAR [CMD]: Initiating ${action} routine...`);
    setTimeout(() => {
      addLog(`SOAR [RESPONSE]: ${action} deployed. Validating integrity...`);
      setTimeout(() => {
        addLog(`SUCCESS: Rule base updated. Host isolated.`);
        setIsExecuting(false);
      }, 1500);
    }, 1000);
  };

  return (
    <div className="space-y-6">
      <PageHeader 
        title="Phase 4: Threat Hunting & SOAR" 
        icon={Crosshair} 
        description="Active response orchestration and autonomous playbook execution."
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card title="Rapid Response Matrix" subtitle="CONTROLLED MITIGATION PROTOCOLS">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <button 
              onClick={() => handleAction('HOST_ISOLATION')}
              disabled={isExecuting}
              className="group p-5 bg-metalbg-elevated/20 border border-metal-border rounded-2xl text-left hover:border-metalgold-main transition-all disabled:opacity-30 relative overflow-hidden"
            >
               <div className="text-metalsilver-muted mb-2 group-hover:text-metalgold-main transition-colors"><ShieldAlert size={24} /></div>
               <div className="text-[11px] font-black text-metaltxt-primary uppercase tracking-widest">Isolate host</div>
               <p className="text-[9px] text-metalsilver-muted mt-2 font-bold uppercase tracking-tighter opacity-70">Sever network plane connectivity.</p>
            </button>
            <button 
              onClick={() => handleAction('IP_BLOCK')}
              disabled={isExecuting}
              className="group p-5 bg-metalbg-elevated/20 border border-metal-border rounded-2xl text-left hover:border-metalgold-main transition-all disabled:opacity-30"
            >
               <div className="text-metalsilver-muted mb-2 group-hover:text-metalgold-main transition-colors"><AlertTriangle size={24} /></div>
               <div className="text-[11px] font-black text-metaltxt-primary uppercase tracking-widest">Deploy Blacklist</div>
               <p className="text-[9px] text-metalsilver-muted mt-2 font-bold uppercase tracking-tighter opacity-70">Update firewall signature rules.</p>
            </button>
            <button 
              onClick={() => handleAction('FULL_TRUNCATE')}
              disabled={isExecuting}
              className="group p-5 bg-metalbg-elevated/20 border border-metal-border rounded-2xl text-left hover:border-metalgold-main transition-all disabled:opacity-30"
            >
               <div className="text-metalsilver-muted mb-2 group-hover:text-metalgold-main transition-colors"><History size={24} /></div>
               <div className="text-[11px] font-black text-metaltxt-primary uppercase tracking-widest">Memory Snap</div>
               <p className="text-[9px] text-metalsilver-muted mt-2 font-bold uppercase tracking-tighter opacity-70">Capture forensic memory state.</p>
            </button>
            <button 
              onClick={() => handleAction('ANOMALY_RESET')}
              disabled={isExecuting}
              className="group p-5 bg-metalbg-elevated/20 border border-metal-border rounded-2xl text-left hover:border-metalgold-main transition-all disabled:opacity-30"
            >
               <div className="text-metalsilver-muted mb-2 group-hover:text-metalgold-main transition-colors"><ShieldCheck size={24} /></div>
               <div className="text-[11px] font-black text-metaltxt-primary uppercase tracking-widest">Re-baseline</div>
               <p className="text-[9px] text-metalsilver-muted mt-2 font-bold uppercase tracking-tighter opacity-70">Reset ML behavioral sensors.</p>
            </button>
          </div>
        </Card>

        <Card title="Tactical Audit Log" subtitle="REAL-TIME OPERATION STATUS">
          <div className="flex-1 bg-[#0E0E10] border border-metal-border rounded-xl p-5 font-mono text-[10px] space-y-3 overflow-y-auto max-h-80 shadow-inner premium-scrollbar">
             {logs.map((log, i) => (
               <div key={i} className="flex space-x-4 group">
                  <span className="text-metalsilver-muted opacity-40 group-hover:opacity-100 transition-opacity whitespace-nowrap">{log.ts}</span>
                  <span className={`font-bold tracking-tight ${log.msg.includes('SUCCESS') ? 'text-metalgold-main' : log.msg.includes('ERROR') ? 'text-red-400' : 'text-metalsilver-main'}`}>
                    {log.msg}
                  </span>
               </div>
             ))}
          </div>
          {isExecuting && (
            <div className="mt-4 flex items-center justify-center space-x-2">
               <div className="w-1.5 h-1.5 rounded-full bg-metalgold-main animate-ping" />
               <span className="text-[9px] font-black text-metalgold-main uppercase tracking-[0.4em]">Executing Protocol...</span>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};
