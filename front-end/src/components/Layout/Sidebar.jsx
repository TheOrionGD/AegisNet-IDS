import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  ActivitySquare, 
  Network, 
  Clock, 
  Crosshair,
  Bell
} from 'lucide-react';
import useStore from '../../store/useStore';

const NavItem = ({ to, icon, label, isActive }) => (
  <Link
    to={to}
    className={`sidebar-link ${isActive ? 'sidebar-link-active' : 'text-metalsilver-muted hover:text-metalsilver-main hover:bg-metalbg-elevated/50'}`}
  >
    <div className={`${isActive ? 'text-metalgold-main' : 'text-metalsilver-muted group-hover:text-metalsilver-main'} transition-colors`}>
      {icon}
    </div>
    <span className="font-bold text-xs uppercase tracking-widest">{label}</span>
  </Link>
);

const Sidebar = () => {
  const isSidebarOpen = useStore((state) => state.isSidebarOpen);
  const location = useLocation();

  const navLinks = [
    { to: '/', label: 'Overview', icon: <LayoutDashboard size={20} /> },
    { to: '/alerts', label: 'Tactical Alerts', icon: <Bell size={20} /> },
    { to: '/incidents', label: 'Incidents', icon: <ShieldAlert size={20} /> },
    { to: '/anomalies', label: 'Anomalies', icon: <ActivitySquare size={20} /> },
    { to: '/ips', label: 'IP Intelligence', icon: <Network size={20} /> },
    { to: '/timeline', label: 'Timeline', icon: <Clock size={20} /> },
    { to: '/phase4', label: 'Threat Hunting', icon: <Crosshair size={20} /> },
  ];



  return (
    <aside 
      className={`fixed inset-y-0 left-0 z-50 bg-metalbg-secondary border-r border-metal-border transition-all duration-300 ${
        isSidebarOpen ? 'w-64' : 'w-20'
      }`}
    >
      <div className="flex flex-col h-full">
        {/* Core Branding */}
        <div className="h-16 flex items-center px-6 border-b border-metal-border">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="text-metalgold-main" size={28} />
            {isSidebarOpen && <span className="text-xl font-bold tracking-wider text-metaltxt-primary uppercase">Aegis<span className="text-metalgold-main">Net</span></span>}
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
          <div className="p-4 border-t border-metal-border">
            <div className="flex items-center space-x-3 text-[10px] text-metalsilver-muted font-bold tracking-widest uppercase">
              <div className="w-2 h-2 rounded-full bg-metalgold-main animate-gold-pulse"></div>
              <span>System Online</span>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};

export default Sidebar;
