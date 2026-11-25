import { Navigate, Route, Routes } from 'react-router-dom';
import { Layout, LoginPage } from './components/Layout';
import { getToken } from './services/api';
import Overview from './pages/Overview';
import Monitoring from './pages/Monitoring';
import EventSubmission from './pages/EventSubmission';
import LogExplorer from './pages/LogExplorer';
import Endpoints from './pages/Endpoints';
import Forwarders from './pages/Forwarders';
import Detection from './pages/Detection';
import Investigation from './pages/Investigation';
import Incidents from './pages/Incidents';
import Response from './pages/Response';
import Agents from './pages/Agents';
import ThreatIntel from './pages/ThreatIntel';
import MitreExplorer from './pages/MitreExplorer';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

function Protected({ children }: { children: React.ReactNode }) {
  if (!getToken()) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <Protected>
            <Layout />
          </Protected>
        }
      >
        <Route path="/" element={<Overview />} />
        <Route path="/monitoring" element={<Monitoring />} />
        <Route path="/submit" element={<EventSubmission />} />
        <Route path="/logs" element={<LogExplorer />} />
        <Route path="/endpoints" element={<Endpoints />} />
        <Route path="/forwarders" element={<Forwarders />} />
        <Route path="/detection" element={<Detection />} />
        <Route path="/investigation" element={<Investigation />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/response" element={<Response />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/intel" element={<ThreatIntel />} />
        <Route path="/mitre" element={<MitreExplorer />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
