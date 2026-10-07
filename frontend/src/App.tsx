import { useState } from "react";
import { BrowserRouter, Link, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "@/api/auth";
import { getToken } from "@/api/client";
import { LiveProvider } from "@/hooks/live";
import { ToastProvider } from "@/components/feedback";
import { ExplainProvider } from "@/components/explain";
import { Button, inputClass } from "@/components/ui";
import { Shell } from "@/layouts/Shell";
import Overview from "@/pages/Overview";
import DigitalTwin from "@/pages/DigitalTwin";
import NetworkPage from "@/pages/Network";
import Devices from "@/pages/Devices";
import DeviceDetail from "@/pages/DeviceDetail";
import Identity from "@/pages/Identity";
import UserDetail from "@/pages/UserDetail";
import RiskPage from "@/pages/Risk";
import Access from "@/pages/Access";
import Policies from "@/pages/Policies";
import DriftPage from "@/pages/Drift";
import Changes from "@/pages/Changes";
import Approvals from "@/pages/Approvals";
import Incidents from "@/pages/Incidents";
import IncidentDetail from "@/pages/IncidentDetail";
import AutoHeal from "@/pages/AutoHeal";
import Runbooks from "@/pages/Runbooks";
import ChaosLab from "@/pages/ChaosLab";
import TimeMachine from "@/pages/TimeMachine";
import WhatIf from "@/pages/WhatIf";
import Dependencies from "@/pages/Dependencies";
import Audit from "@/pages/Audit";
import ChatOps from "@/pages/ChatOps";
import Reports from "@/pages/Reports";
import Operations from "@/pages/Operations";
import Troubleshooting from "@/pages/Troubleshooting";
import SystemPage from "@/pages/System";

function KeyLogin({ onSubmit }: { onSubmit: (key: string) => Promise<void> }) {
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  return (
    <div className="flex h-full items-center justify-center p-6">
      <form className="w-[min(420px,100%)] rounded-md border border-line bg-panel p-6" onSubmit={(e) => { e.preventDefault(); onSubmit(key).catch(() => setError("That key was not accepted.")); }}>
        <h1 className="font-cond text-2xl font-semibold">NEXUS OMNIS</h1>
        <p className="mb-4 text-sm text-muted">Demo login is disabled. Enter an API key configured in NEXUS_API_KEYS.</p>
        <input type="password" value={key} onChange={(e) => setKey(e.target.value)} aria-label="API key" className={`${inputClass} mb-3 w-full`} />
        {error && <p className="mb-2 text-sm text-crit">{error}</p>}
        <Button variant="primary" type="submit">Sign in</Button>
      </form>
    </div>
  );
}

function NotFound() {
  return <div className="py-20 text-center"><h1 className="font-cond text-2xl font-semibold">Page not found</h1><Link to="/" className="text-info hover:underline">Back to overview</Link></div>;
}

function Gate() {
  const { ready, principal, useKey } = useAuth();
  if (!ready) return <div className="flex h-full items-center justify-center font-cond text-lg text-muted">Connecting to NEXUS…</div>;
  if (!principal) return <KeyLogin onSubmit={useKey} />;
  return (
    <LiveProvider token={getToken()} key={principal.user_id}>
      <ExplainProvider>
        <BrowserRouter>
          <Shell>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/twin" element={<DigitalTwin />} />
              <Route path="/network" element={<NetworkPage />} />
              <Route path="/devices" element={<Devices />} />
              <Route path="/devices/:id" element={<DeviceDetail />} />
              <Route path="/identity" element={<Identity />} />
              <Route path="/identity/:id" element={<UserDetail />} />
              <Route path="/risk" element={<RiskPage />} />
              <Route path="/access" element={<Access />} />
              <Route path="/policies" element={<Policies />} />
              <Route path="/drift" element={<DriftPage />} />
              <Route path="/changes" element={<Changes />} />
              <Route path="/approvals" element={<Approvals />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/incidents/:id" element={<IncidentDetail />} />
              <Route path="/autoheal" element={<AutoHeal />} />
              <Route path="/runbooks" element={<Runbooks />} />
              <Route path="/chaos" element={<ChaosLab />} />
              <Route path="/timemachine" element={<TimeMachine />} />
              <Route path="/whatif" element={<WhatIf />} />
              <Route path="/dependencies" element={<Dependencies />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="/chatops" element={<ChatOps />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/operations" element={<Operations />} />
              <Route path="/troubleshooting" element={<Troubleshooting />} />
              <Route path="/system" element={<SystemPage />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Shell>
        </BrowserRouter>
      </ExplainProvider>
    </LiveProvider>
  );
}

export default function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <Gate />
      </AuthProvider>
    </ToastProvider>
  );
}
