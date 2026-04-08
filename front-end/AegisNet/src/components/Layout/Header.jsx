import { Bell, Menu, Search, Loader } from 'lucide-react';
import useStore from '../../store/useStore';
import { formatDistanceToNow } from 'date-fns';

const Header = () => {
  const { toggleSidebar, lastUpdated } = useStore();

  return (
    <header className="h-16 bg-bgSecondary border-b border-bgElevated flex items-center justify-between px-6 z-40 sticky top-0">
      {/* Left side */}
      <div className="flex items-center space-x-4">
        <button 
          onClick={toggleSidebar}
          className="text-silverMuted hover:text-textPrimary transition-colors"
        >
          <Menu size={24} />
        </button>
        <h2 className="text-lg font-semibold tracking-wide text-silverMain">Dashboard Overview</h2>
      </div>

      {/* Right side */}
      <div className="flex items-center space-x-6">
        {/* Search */}
        <div className="relative relative-group hidden md:block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-silverMuted" size={18} />
          <input 
            type="text" 
            placeholder="Search IP, Incident, Rule..." 
            className="bg-bgElevated border border-bgElevated focus:border-goldMain text-textPrimary text-sm rounded-lg pl-10 pr-4 py-2 outline-none w-64 transition-all"
          />
        </div>

        {/* Live Refresh Indicator */}
        <div className="flex items-center space-x-2 text-xs font-medium text-silverMuted mr-4">
          <Loader className="animate-spin text-goldMain" size={14} />
          <span>Live • Updated {lastUpdated ? formatDistanceToNow(new Date(lastUpdated), { addSuffix: true }) : 'just now'}</span>
        </div>

        {/* Notifications */}
        <button className="relative text-silverMuted hover:text-goldMain transition-colors">
          <Bell size={20} />
          <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-bgSecondary"></span>
        </button>

        {/* Profile Mock */}
        <div className="w-8 h-8 rounded-full bg-goldMain flex items-center justify-center text-bgMain font-bold text-sm shadow-md">
          A
        </div>
      </div>
    </header>
  );
};

export default Header;
