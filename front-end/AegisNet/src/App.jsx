import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/Layout/Layout';
import DashboardOverview from './pages/Dashboard';
import { IncidentsPage, AnomaliesPage, IPsPage, TimelinePage, Phase4Page } from './pages/OtherPages';

// Setup React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<DashboardOverview />} />
            <Route path="incidents" element={<IncidentsPage />} />
            <Route path="anomalies" element={<AnomaliesPage />} />
            <Route path="ips" element={<IPsPage />} />
            <Route path="timeline" element={<TimelinePage />} />
            <Route path="phase4" element={<Phase4Page />} />
          </Route>
        </Routes>
      </Router>
    </QueryClientProvider>
  );
}

export default App;
