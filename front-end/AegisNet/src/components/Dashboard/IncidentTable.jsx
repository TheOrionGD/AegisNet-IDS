import { FixedSizeList as List } from 'react-window';
import Badge from '../UI/Badge';
import { format } from 'date-fns';

const IncidentTable = ({ incidents }) => {
  // Empty state
  if (!incidents || incidents.length === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-text-muted border border-dashed border-border rounded-lg bg-bg-secondary/30">
        <p className="font-mono text-sm uppercase tracking-widest">No Tactical Signals Detected</p>
      </div>
    );
  }

  // Row Renderer for virtualized list
  const Row = ({ index, style }) => {
    const item = incidents[index];
    const isEven = index % 2 === 0;

    return (
      <div
        style={style}
        className={`flex items-center px-4 py-2 border-b border-border hover:bg-bg-accent/50 transition-colors cursor-pointer group ${isEven ? 'bg-bg-secondary' : 'bg-bg-main/50'}`}
      >
        <div className="flex-1 min-w-[120px] font-mono text-[10px] text-text-muted group-hover:text-primary transition-colors">{item.id}</div>
        <div className="flex-1 min-w-[160px] text-xs text-text-secondary">
          {format(new Date(item.timestamp), 'MMM dd, HH:mm:ss')}
        </div>
        <div className="w-24">
          <Badge variant={item.severity}>{item.severity}</Badge>
        </div>
        <div className="flex-1 min-w-[140px] font-mono text-xs text-text-main">{item.source_ip || item.src_ip}:{item.source_port || item.src_port || '*'}</div>
        <div className="flex-1 min-w-[140px] font-mono text-xs text-text-main">{item.dest_ip || item.dst_ip}:{item.dest_port || item.dst_port || '*'}</div>
        <div className="w-32 text-xs truncate text-text-secondary capitalize">{item.attack_type || 'Unknown'}</div>
        <div className="w-20">
          <Badge variant={item.status || 'open'}>{item.status || 'OPEN'}</Badge>
        </div>
        <div className="flex-[2] text-xs truncate text-text-main px-2" title={item.description}>
          {item.description}
        </div>
      </div>
    );
  };

  return (
    <div className="border border-border rounded-lg overflow-hidden bg-bg-secondary shadow-inner">
      {/* Table Header */}
      <div className="flex items-center px-4 py-3 bg-bg-elevated/50 border-b border-border text-[10px] font-bold text-text-secondary uppercase tracking-tighter backdrop-blur-md">
        <div className="flex-1 min-w-[120px]">Vector ID</div>
        <div className="flex-1 min-w-[160px]">Timestamp</div>
        <div className="w-24">Severity</div>
        <div className="flex-1 min-w-[140px]">Source</div>
        <div className="flex-1 min-w-[140px]">Destination</div>
        <div className="w-32">Classification</div>
        <div className="w-20">Status</div>
        <div className="flex-[2] px-2">Operational Intelligence</div>
      </div>

      {/* Virtualized Body */}
      <List
        height={400} // fixed height container
        itemCount={incidents.length}
        itemSize={44} // row height
        width="100%"
        className="premium-scrollbar"
      >
        {Row}
      </List>
    </div>
  );
};

export default IncidentTable;
