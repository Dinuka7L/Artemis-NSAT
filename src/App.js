import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import DeviceManagement from './pages/DeviceManagement';
import DeviceConfiguration from './pages/DeviceConfiguration';
import AttackMitigation from './pages/AttackMitigation';
import FrameworkControls from './pages/FrameworkControls';
import NetworkCompliance from './pages/NetworkCompliance';
import Automation from './pages/Automation';
import Reports from './pages/Reports';
import Terminal from './pages/Terminal';

function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/device-management" element={<DeviceManagement />} />
          <Route path="/device-configuration" element={<DeviceConfiguration />} />
          <Route path="/attack-mitigation" element={<AttackMitigation />} />
          <Route path="/framework-controls" element={<FrameworkControls />} />
          <Route path="/network-compliance" element={<NetworkCompliance />} />
          <Route path="/automation" element={<Automation />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/terminal" element={<Terminal />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;