import React, { useState } from 'react';
import { Bell, Menu, Search, Loader, LogOut, User as UserIcon, Shield } from 'lucide-react';
import useStore from '../../store/useStore';
import { formatDistanceToNow } from 'date-fns';
import { useNavigate } from 'react-router-dom';

const Header = () => {
  const toggleSidebar = useStore((state) => state.toggleSidebar);
  const lastUpdated = useStore((state) => state.lastUpdated);
  const user = useStore((state) => state.user);
  const logout = useStore((state) => state.logout);
  const navigate = useNavigate();
  
  const [searchValue, setSearchValue] = useState("");

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <header className="h-16 bg-metal-glass backdrop-blur-xl border-b border-metal-border flex items-center justify-between px-6 z-40 sticky top-0 transition-all shadow-lg">
      {/* Left side */}
      <div className="flex items-center space-x-4">
        <button 
          onClick={toggleSidebar}
          className="w-10 h-10 flex items-center justify-center rounded-lg text-metalsilver-muted hover:text-metalgold-main hover:bg-metalgold-main/5 transition-all duration-300 border border-transparent hover:border-metalgold-main/20"
        >
          <Menu size={20} />
        </button>
        <div className="flex flex-col">
          <h2 className="text-xs font-black tracking-[0.2em] text-metalsilver-main uppercase leading-tight">Tactical Access</h2>
          <div className="flex items-center space-x-1.5">
            <div className="w-1 h-1 rounded-full bg-metalgold-main animate-gold-pulse" />
            <span className="text-[9px] text-metalsilver-muted font-mono uppercase tracking-tighter">AEGIS-NODE-{user?.username?.toUpperCase() || 'PRIMARY'}</span>
          </div>
        </div>
      </div>

      {/* Right side */}
      <div className="flex items-center space-x-6">
        {/* Search */}
        <div className="relative group hidden lg:block">
          <Search className={`absolute left-3 top-1/2 -translate-y-1/2 transition-colors ${searchValue ? 'text-metalgold-main' : 'text-metalsilver-muted group-hover:text-metalsilver-main'}`} size={14} />
          <input 
            type="text" 
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            placeholder="SEARCH THREAT VECTORS..." 
            className="input-field w-72 pl-10 pr-4 py-1.5 placeholder:text-metalsilver-muted/30 uppercase tracking-widest text-[10px]"
          />
        </div>

        {/* Live Refresh Indicator */}
        <div className="flex items-center space-x-3 px-4 py-1.5 rounded-full bg-metalbg-main/30 border border-metal-border">
          <Loader className="animate-spin text-metalgold-main" size={10} />
          <div className="flex flex-col">
             <span className="text-[8px] text-metalsilver-muted uppercase font-black tracking-widest">Live Uplink</span>
             <span className="text-[10px] text-metalgold-main font-mono leading-none">
               {lastUpdated ? formatDistanceToNow(new Date(lastUpdated), { addSuffix: true }) : 'Syncing...'}
             </span>
          </div>
        </div>

        {/* Tactical Alerts */}
        <button 
          onClick={() => navigate('/alerts')}
          className="relative w-10 h-10 flex items-center justify-center rounded-xl bg-metalbg-main/30 border border-metal-border text-metalsilver-muted hover:text-metalgold-main hover:border-metalgold-main/30 transition-all group"
        >
          <Bell size={18} className="group-hover:animate-bounce" />
          <span className="absolute top-2.5 right-2.5 w-1.5 h-1.5 bg-metalgold-main rounded-full shadow-[0_0_8px_var(--gold-main)]"></span>
        </button>

        {/* User Profile & Logout */}
        <div className="flex items-center space-x-3 pl-4 border-l border-metal-border group">
          <div className="text-right hidden sm:block">
            <div className="text-[9px] font-black text-metalsilver-main uppercase tracking-widest">{user?.username || 'Tactical Cmdr'}</div>
            <div className="text-[8px] text-metalgold-main font-mono">AUTH_LEVEL_{user?.level || '01'}</div>
          </div>
          <div className="relative">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-metalgold-main to-metalgold-hover flex items-center justify-center text-metalbg-main font-black text-xs shadow-lg shadow-metalgold-main/20 border border-white/10 hover:scale-105 transition-transform cursor-pointer">
              {user?.username?.substring(0, 2).toUpperCase() || 'OP'}
            </div>
            <button 
              onClick={handleLogout}
              className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-m-critical flex items-center justify-center text-white opacity-0 group-hover:opacity-100 transition-opacity shadow-lg"
              title="Logout"
            >
              <LogOut size={10} />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;

