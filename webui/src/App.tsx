import { Navigate, Outlet, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Settings from "./pages/Settings";
import RequireAuth from "./components/RequireAuth";
import Integrations from "./pages/Integrations";
import IntegrationWorkspace from "./pages/IntegrationWorkspace";
import Discover from "./pages/Discover";
import Alerts from "./pages/Alerts";
import Rules from "./pages/Rules";
import Profiles from "./pages/Profiles";
import Assets from "./pages/Assets";
import Topology from "./pages/Topology";
import Shell from "./components/Shell";

function ProtectedLayout() {
  return (
    <RequireAuth>
      <Shell>
        <Outlet />
      </Shell>
    </RequireAuth>
  );
}
export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedLayout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/discover" element={<Discover />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/assetsman" element={<Assets />} />
        <Route path="/topology" element={<Topology />} />
        <Route path="/integrations/:id" element={<IntegrationWorkspace />} />
        <Route
          path="/rules"
          element={
            <RequireAuth requireAdmin>
              <Rules />
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
        <Route
          path="/integrations"
          element={
            <RequireAuth requireAdmin>
              <Integrations />
            </RequireAuth>
          }
        />
        <Route
          path="/profiles"
          element={
            <RequireAuth requireAdmin>
              <Profiles />
            </RequireAuth>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
