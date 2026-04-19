import { FixedSizeList as List } from 'react-window';
import Badge from '../UI/Badge';
import { format } from 'date-fns';

const formatTimestamp = (item) => {
  const ts = item.timestamp || item.start_time || item.end_time;
  if (!ts) return 'PENDING';
  try {
    const date = new Date(ts);
    if (isNaN(date.getTime())) return 'PENDING';
    return format(date, 'MMM dd | HH:mm:ss');
  } catch {
    return 'PENDING';
  }
};

const IncidentTable = ({ incidents }) => {
  if (!incidents || incidents.length === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-metalsilver-muted border border-dashed border-metal-border rounded-lg bg-metalbg-secondary/30">
        <p className="font-mono text-sm uppercase tracking-widest">No Tactical Signals Detected</p>
      </div>
    );
  }

  const Row = ({ index, style }) => {
    const item = incidents[index];
    const isEven = index % 2 === 0;

    return (
      <div
        style={style}
        className={`flex items-center px-4 py-2 border-b border-metal-border transition-colors cursor-pointer group hover:bg-[#2A2B2F] ${isEven ? 'bg-metalbg-main' : 'bg-metalbg-secondary'}`}
      >
        <div className="flex-1 min-w-[120px] font-mono text-[9px] text-metalsilver-muted group-hover:text-metalgold-main transition-colors uppercase font-bold">{item.id}</div>
        <div className="flex-1 min-w-[160px] text-[10px] text-metalsilver-muted font-bold uppercase">
          {formatTimestamp(item)}
        </div>
        <div className="w-24 px-1">
          <Badge variant={item.severity}>{item.severity}</Badge>
        </div>
        <div className="flex-1 min-w-[140px] font-mono text-[10px] text-metalsilver-main font-bold">{item.source_ip || item.src_ip}</div>
        <div className="flex-1 min-w-[140px] font-mono text-[10px] text-metalsilver-main font-bold">{item.dest_ip || item.dst_ip}</div>
        <div className="w-32 text-[10px] font-black uppercase text-metaltxt-primary tracking-tighter">{item.attack_type || 'Unknown Vector'}</div>
        <div className="w-20">
          <Badge variant={item.status || 'open'}>{item.status || 'OPEN'}</Badge>
        </div>
        <div className="flex-[2] text-[10px] truncate text-metalsilver-muted px-2 italic" title={item.description}>
          {item.description}
        </div>
      </div>
    );
  };

  return (
    <div className="border border-metal-border rounded-xl overflow-hidden bg-metalbg-secondary shadow-2xl">
      <div className="flex items-center px-4 py-3 bg-metalbg-elevated border-b border-metal-border text-[9px] font-black text-metalsilver-muted uppercase tracking-[0.2em] backdrop-blur-md">
        <div className="flex-1 min-w-[120px]">Vector Signature</div>
        <div className="flex-1 min-w-[160px]">Temporal Stamp</div>
        <div className="w-24 px-1">Severity</div>
        <div className="flex-1 min-w-[140px]">Source Origin</div>
        <div className="flex-1 min-w-[140px]">Dest Target</div>
        <div className="w-32">Classification</div>
        <div className="w-20">Status</div>
        <div className="flex-[2] px-2">Operational Data</div>
      </div>

      <List
        height={400}
        itemCount={incidents.length}
        itemSize={44}
        width="100%"
        className="premium-scrollbar"
      >
        {Row}
      </List>
    </div>
  );
};

export default IncidentTable;