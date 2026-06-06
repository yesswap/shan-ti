"use client";
import { useState } from "react";
import Link from "next/link";
import { auth } from "@/lib/api";

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [step, setStep] = useState<"form" | "sent" | "set_key">("form");
  const [apiKey, setApiKey] = useState("");
  const [manualKey, setManualKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleRegister = async () => {
    if (!email) return;
    setLoading(true);
    setError("");
    try {
      await auth.register(email, name);
      setStep("sent");
    } catch (e: any) {
      setError(e.message || "Registration failed.");
    } finally {
      setLoading(false);
    }
  };

  const handleSaveKey = () => {
    if (!manualKey.trim()) return;
    localStorage.setItem("tl_api_key", manualKey.trim());
    window.location.href = "/";
  };

  const PLAN_FEATURES = [
    { icon: "🎯", text: "130+ threat actor profiles (MITRE ATT&CK)" },
    { icon: "🔗", text: "Live IOC feeds from OTX + vendor blogs" },
    { icon: "🔧", text: "ATT&CK TTP mapping per actor" },
    { icon: "🔄", text: "IOC pivot — link any indicator to actors" },
    { icon: "⏱️", text: "Automatic IOC aging & TTL expiry" },
    { icon: "📡", text: "10 req/min · 500 req/day (free plan)" },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center px-4">
      <Link href="/" className="flex items-center gap-2 mb-10">
        <div className="w-8 h-8 bg-sky-500 rounded-lg flex items-center justify-center text-white font-bold text-sm">TL</div>
        <span className="font-bold text-xl">ThreatLens</span>
      </Link>

      <div className="w-full max-w-md">
        {step === "form" && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8">
            <h1 className="text-2xl font-bold mb-2">Get your free API key</h1>
            <p className="text-slate-400 text-sm mb-6">Register with your email. No payment required.</p>

            <div className="space-y-3 mb-6">
              <input type="text" placeholder="Name (optional)" value={name} onChange={e => setName(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-sky-500" />
              <input type="email" placeholder="your@email.com" value={email} onChange={e => setEmail(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleRegister()}
                className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-sky-500" />
            </div>

            {error && <div className="text-red-400 text-sm mb-4 bg-red-500/10 border border-red-500/20 rounded-lg p-3">{error}</div>}

            <button onClick={handleRegister} disabled={loading || !email}
              className="w-full bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold py-3 rounded-xl transition-colors">
              {loading ? "Sending..." : "Send verification email →"}
            </button>

            <div className="mt-6 space-y-2">
              {PLAN_FEATURES.map(f => (
                <div key={f.text} className="flex items-center gap-2.5 text-sm text-slate-400">
                  <span>{f.icon}</span>
                  <span>{f.text}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {step === "sent" && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center">
            <div className="text-5xl mb-4">📧</div>
            <h2 className="text-xl font-bold mb-2">Check your inbox</h2>
            <p className="text-slate-400 text-sm mb-6">
              We sent a verification link to <strong className="text-white">{email}</strong>.
              Click it to get your API key.
            </p>
            <div className="bg-slate-800 rounded-xl p-4 text-left mb-6">
              <p className="text-slate-400 text-xs mb-1">After verifying, paste your API key below to start using ThreatLens:</p>
            </div>
            <input type="text" placeholder="tl_xxxxxxxxxx..." value={manualKey} onChange={e => setManualKey(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm font-mono focus:outline-none focus:border-sky-500 mb-3" />
            <button onClick={handleSaveKey} disabled={!manualKey.trim()}
              className="w-full bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold py-3 rounded-xl transition-colors">
              Save key & open dashboard →
            </button>
            <p className="text-slate-600 text-xs mt-4">Key is saved in your browser (localStorage)</p>
          </div>
        )}
      </div>
    </div>
  );
}
