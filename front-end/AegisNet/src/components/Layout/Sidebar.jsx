import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  ActivitySquare, 
  Network, 
  Clock, 
  Crosshair 
} from 'lucide-react';
import useStore from '../../store/useStore';

const NavItem = ({ to, icon, label, isActive }) => (
  <Link
    to={to}
    className={`flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors duration-200 ${
      isActive 
        ? 'bg-bgElevated text-goldMain border-l-2 border-goldMain' 
        : 'text-silverMain hover:bg-bgElevated hover:text-silverSoft'
    }`}
  >
    {icon}
    <span className="font-medium text-sm">{label}</span>
  </Link>
);

const Sidebar = () => {
  const isSidebarOpen = useStore((state) => state.isSidebarOpen);
  const location = useLocation();

  const navLinks = [
    { to: '/', label: 'Overview', icon: <LayoutDashboard size={20} /> },
    { to: '/incidents', label: 'Incidents', icon: <ShieldAlert size={20} /> },
    { to: '/anomalies', label: 'Anomalies', icon: <ActivitySquare size={20} /> },
    { to: '/ips', label: 'IP Intelligence', icon: <Network size={20} /> },
    { to: '/timeline', label: 'Timeline', icon: <Clock size={20} /> },
    { to: '/phase4', label: 'Threat Hunting', icon: <Crosshair size={20} /> },
  ];

  return (
    <aside 
      className={`fixed inset-y-0 left-0 z-50 bg-bgSecondary border-r border-bgElevated transition-all duration-300 ${
        isSidebarOpen ? 'w-64' : 'w-20'
      }`}
    >
      <div className="flex flex-col h-full">
        {/* Core Branding */}
        <div className="h-16 flex items-center px-6 border-b border-bgElevated">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="text-goldMain" size={28} />
            {isSidebarOpen && <span className="text-xl font-bold tracking-wider text-textPrimary">Aegis<span className="text-goldMain">Net</span></span>}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-6 px-3 space-y-1">
          {navLinks.map((link) => (
            <NavItem 
              key={link.to}
              to={link.to}
              label={isSidebarOpen ? link.label : ''}
              icon={link.icon}
              isActive={location.pathname === link.to}
            />
          ))}
        </nav>

        {/* System Status Footer */}
        {isSidebarOpen && (
          <div className="p-4 border-t border-bgElevated">
            <div className="flex items-center space-x-3 text-xs text-silverMuted">
              <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
              <span>System Online</span>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};

export default Sidebar;
