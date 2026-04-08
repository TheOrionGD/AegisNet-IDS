import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { format } from 'date-fns';

const AnomalyChart = ({ data }) => {
  if (!data || data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-text-muted border border-dashed border-border rounded-lg bg-bg-secondary/20">
        <p className="font-mono text-xs uppercase tracking-widest">Awaiting Vector Signal Data...</p>
      </div>
    );
  }

  // Use the css variables for charts formatting
  const primaryColor = '#2f81f7';
  const gridColor = 'rgba(255, 255, 255, 0.05)';

  // Format data for chart
  const chartData = data.map(item => ({
    time: format(new Date(item.timestamp), 'HH:mm:ss'),
    score: (item.ml_score || item.confidence_score || 0) * 100, // normalize to 100
  })).reverse().slice(-20); // Show last 20 points in chronological order

  return (
    <div className="h-full w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={primaryColor} stopOpacity={0.3}/>
              <stop offset="95%" stopColor={primaryColor} stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={gridColor} vertical={false} />
          <XAxis 
            dataKey="time" 
            stroke="#484f58" 
            fontSize={9} 
            tickLine={false} 
            axisLine={false} 
            dy={10}
          />
          <YAxis 
            stroke="#484f58" 
            fontSize={9} 
            tickLine={false} 
            axisLine={false} 
            domain={[0, 100]} 
            dx={-10}
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: '#161b22', 
              borderColor: 'rgba(255,255,255,0.1)', 
              borderRadius: '8px',
              fontSize: '12px',
              color: '#e6edf3'
            }}
            itemStyle={{ color: primaryColor }}
            cursor={{ stroke: primaryColor, strokeWidth: 1 }}
          />
          <Area 
            type="monotone" 
            dataKey="score" 
            stroke={primaryColor} 
            strokeWidth={2}
            fillOpacity={1} 
            fill="url(#colorScore)" 
            isAnimationActive={true}
            animationDuration={1000}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AnomalyChart;
