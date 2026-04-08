const Placeholder = ({ title }) => (
  <div className="h-full flex flex-col items-center justify-center animate-in fade-in duration-500">
    <div className="w-16 h-16 border-4 border-t-goldMain border-bgElevated rounded-full animate-spin mb-6"></div>
    <h2 className="text-2xl font-bold text-silverMain mb-2">{title}</h2>
    <p className="text-silverMuted">This module is currently initializing...</p>
  </div>
);

export const IncidentsPage = () => <Placeholder title="Incident Management" />;
export const AnomaliesPage = () => <Placeholder title="ML Anomalies View" />;
export const IPsPage = () => <Placeholder title="IP Intelligence" />;
export const TimelinePage = () => <Placeholder title="Attack Timeline" />;
export const Phase4Page = () => <Placeholder title="Phase 4: Threat Hunting & SOAR" />;
