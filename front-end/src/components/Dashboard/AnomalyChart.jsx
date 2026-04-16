import React, { useMemo } from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { format } from 'date-fns';
import Card from '../UI/Card';

const AnomalyChart = ({ data }) => {
  // Format data for chart (Hook must be called before early return)
  const chartData = useMemo(() => {
    if (!data) return [];
    return data.reduce((acc, item) => {
      const timestamp = item?.timestamp || item?.time || item?.created_at;
      const date = new Date(timestamp);
      if (Number.isNaN(date.getTime())) return acc;
      return [...acc, {
        time: format(date, 'HH:mm:ss'),
        score: (item.ml_score || 0) * 100,
      }];
    }, []).reverse().slice(-30);
  }, [data]);

  if (!data || data.length === 0) {
    return (
      <Card title="Temporal Anomaly Density" subtitle="AWAITING VECTOR SIGNALS">
        <div className="h-64 flex items-center justify-center text-metalsilver-muted border border-dashed border-metal-border rounded-xl bg-metalbg-secondary/20">
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] font-black">Link Pending...</p>
        </div>
      </Card>
    );
  }

  // Use the metallic palette
  const primaryColor = '#D4AF37'; // Gold
  const secondaryColor = '#8F8F8F'; // Silver Muted
  const gridColor = 'rgba(143, 143, 143, 0.1)';

  return (
    <Card className="h-full min-h-[400px]" title="Temporal Anomaly Density" subtitle="ML-DRIVEN THREAT DETECTION">
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={primaryColor} stopOpacity={0.4}/>
              <stop offset="95%" stopColor={primaryColor} stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke={gridColor} vertical={false} />
          <XAxis 
            dataKey="time" 
            stroke={secondaryColor} 
            fontSize={9} 
            tickLine={false} 
            axisLine={false} 
            dy={10}
          />
          <YAxis 
            stroke={secondaryColor} 
            fontSize={9} 
            tickLine={false} 
            axisLine={false} 
            domain={[0, 100]} 
            dx={-10}
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: '#1A1A1D', 
              borderColor: 'rgba(212, 175, 55, 0.2)', 
              borderRadius: '8px',
              fontSize: '10px',
              color: '#F5F5F5',
              textTransform: 'uppercase',
              fontWeight: 'bold',
              border: '1px solid rgba(143, 143, 143, 0.2)'
            }}
            itemStyle={{ color: primaryColor }}
            cursor={{ stroke: primaryColor, strokeWidth: 1 }}
          />
          <Area 
            type="monotone" 
            dataKey="score" 
            stroke={primaryColor} 
            strokeWidth={3}
            fillOpacity={1} 
            fill="url(#colorScore)" 
            isAnimationActive={true}
            animationDuration={1000}
          />
        </AreaChart>
      </ResponsiveContainer>
    </Card>
  );
};

export default AnomalyChart;
