import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import useStore from '../../store/useStore';

const Layout = () => {
  const isSidebarOpen = useStore((state) => state.isSidebarOpen);

  return (
    <div className="min-h-screen bg-bgMain text-textPrimary flex">
      {/* Fixed Sidebar */}
      <Sidebar />
      
      {/* Main Content Wrapper */}
      <div 
        className={`flex-1 flex flex-col min-h-screen transition-all duration-300 ${
          isSidebarOpen ? 'ml-64' : 'ml-20'
        }`}
      >
        <Header />
        
        {/* Scrollable Page Content */}
        <main className="flex-1 p-6 overflow-x-hidden overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;
