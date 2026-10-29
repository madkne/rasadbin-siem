import { Navigate, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Settings from "./pages/Settings";
import RequireAuth from "./components/RequireAuth";
import Integrations from "./pages/Integrations";
import IntegrationWorkspace from "./pages/IntegrationWorkspace";
import Discover from "./pages/Discover";
import Alerts from "./pages/Alerts";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/login" element={<Login />} />

      <Route
        path="/dashboard"
        element={
          <RequireAuth>
            <Dashboard />
          </RequireAuth>
        }
      />

      <Route
        path="/settings"
        element={
          <RequireAuth requireAdmin>
            <Settings />
          </RequireAuth>
        }
      />

      {/* Integration management: administrators only */}
      <Route
        path="/integrations"
        element={
          <RequireAuth requireAdmin>
            <Integrations />
          </RequireAuth>
        }
      />

      {/* Individual integration workspace */}
      <Route
        path="/integrations/:id"
        element={
          <RequireAuth>
            <IntegrationWorkspace />
          </RequireAuth>
        }
      />

      <Route
        path="/discover"
        element={
          <RequireAuth>
            <Discover />
          </RequireAuth>
        }
      />

      <Route
        path="/alerts"
        element={
          <RequireAuth>
            <Alerts />
          </RequireAuth>
        }
      />

      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
