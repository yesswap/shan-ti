"use client";
import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { actors, ActorDetail, Indicator, TTP } from "@/lib/api";

const STATUS_COLOR: Record<string, string> = {
  fresh: "text-emerald-400",
  stale: "text-yellow-400",
  expired: "text-slate-600",
};

const CONFIDENCE_BADGE: Record<string, string> = {
  confirmed: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30",
  high: "bg-green-500/20 text-green-300 border border-green-500/30",
  medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30",
  low: "bg-orange-500/20 text-orange-300 border border-orange-500/30",
  unknown: "bg-slate-500/20 text-slate-400 border border-slate-500/30",
};

const TACTIC_ORDER = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command And Control",
  "Exfiltration", "Impact",
];

function AttackHeatmap({ ttps }: { ttps: TTP[] }) {
  const byTactic: Record<string, TTP[]> = {};
  for (const ttp of ttps) {
    const t = ttp.tactic || "Unknown";
    if (!byTactic[t]) byTactic[t] = [];
    byTactic[t].push(ttp);
  }

  const sorted = TACTIC_ORDER.filter(t => byTactic[t]).concat(
    Object.keys(byTactic).filter(t => !TACTIC_ORDER.includes(t))
  );

  return (
    <div className="space-y-3">
      {sorted.map(tactic => (
        <div key={tactic}>
          <div className="text-xs text-slate-500 font-medium mb-1.5 uppercase tracking-wider">{tactic}</div>
          <div className="flex flex-wrap gap-1.5">
            {byTactic[tactic]?.map(ttp => (
              <a
                key={ttp.technique_id}
                href={`https://attack.mitre.org/techniques/${ttp.technique_id.replace(".", "/")}`}
                target="_blank"
                rel="noopener noreferrer"
                title={ttp.technique_name}
                className="text-xs bg-sky-900/60 text-sky-300 border border-sky-700/50 px-2 py-1 rounded hover:bg-sky-800/60 transition-colors"
              >
                {ttp.technique_id}
              </a>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function IndicatorRow({ ind }: { ind: Indicator }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(ind.value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <tr className="border-b border-slate-800/50 hover:bg-slate-800/30 text-sm">
      <td className="px-4 py-2.5">
        <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono uppercase">{ind.type}</span>
      </td>
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="font-mono text-slate-200 text-xs break-all">{ind.value.length > 60 ? ind.value.slice(0, 60) + "…" : ind.value}</span>
          <button onClick={copy} className="text-slate-600 hover:text-slate-400 text-xs shrink-0">
            {copied ? "✓" : "⎘"}
          </button>
        </div>
      </td>
      <td className="px-4 py-2.5">
        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${CONFIDENCE_BADGE[ind.confidence] || CONFIDENCE_BADGE.unknown}`}>
          {ind.confidence}
        </span>
      </td>
      <td className="px-4 py-2.5">
        <span className={`text-xs font-medium ${STATUS_COLOR[ind.status]}`}>{ind.status}</span>
      </td>
      <td className="px-4 py-2.5 text-slate-500 text-xs">
        {ind.last_seen ? new Date(ind.last_seen).toLocaleDateString() : "—"}
      </td>
      <td className="px-4 py-2.5 text-slate-500 text-xs">{ind.source}</td>
    </tr>
  );
}

export default function ActorDetailPage() {
  const params = useParams();
  const id = Number(params.id);
  const [actor, setActor] = useState<ActorDetail | null>(null);
  const [iocs, setIocs] = useState<Indicator[]>([]);
  const [totalIocs, setTotalIocs] = useState(0);
  const [tab, setTab] = useState<"overview" | "indicators" | "ttps" | "malware">("overview");
  const [loading, setLoading] = useState(true);
  const [iocPage, setIocPage] = useState(1);
  const [iocType, setIocType] = useState("");

  useEffect(() => {
    actors.get(id).then(setActor).catch(() => {}).finally(() => setLoading(false));
  }, [id]);

  useEffect(() => {
    if (tab !== "indicators") return;
    actors.indicators(id, { page: iocPage, ioc_type: iocType || undefined }).then(res => {
      setIocs(res.results);
      setTotalIocs(res.total);
    });
  }, [id, tab, iocPage, iocType]);

  if (loading) return <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400">Loading...</div>;
  if (!actor) return <div className="min-h-screen bg-slate-950 flex items-center justify-center text-red-400">Actor not found.</div>;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 bg-sky-500 rounded-lg flex items-center justify-center text-white font-bold text-sm">TL</div>
            <span className="font-semibold text-lg">ThreatLens</span>
          </Link>
          <span className="text-slate-600">/</span>
          <span className="text-slate-400">{actor.name}</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Actor header */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <h1 className="text-2xl font-bold text-white">{actor.name}</h1>
                {actor.mitre_id && (
                  <a href={`https://attack.mitre.org/groups/${actor.mitre_id}`} target="_blank" rel="noopener noreferrer"
                    className="text-sm bg-sky-900/50 text-sky-300 border border-sky-700/50 px-2 py-0.5 rounded hover:bg-sky-800/50">
                    {actor.mitre_id} ↗
                  </a>
                )}
              </div>
              {actor.aliases.length > 0 && (
                <div className="text-slate-400 text-sm mb-3">Also known as: {actor.aliases.join(", ")}</div>
              )}
              <div className="flex items-center gap-4 text-sm">
                {actor.nation_state && <span className="text-slate-300">🌏 {actor.nation_state}</span>}
                {actor.sponsor && <span className="text-slate-400">Sponsor: {actor.sponsor}</span>}
                {actor.active_since && <span className="text-slate-400">Active since {actor.active_since}</span>}
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                  actor.active_status === "active" ? "bg-red-500/20 text-red-300" :
                  actor.active_status === "inactive" ? "bg-slate-500/20 text-slate-400" :
                  "bg-yellow-500/20 text-yellow-300"
                }`}>{actor.active_status}</span>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3 text-center">
              {[
                { label: "IOCs", value: actor.indicator_count },
                { label: "TTPs", value: actor.ttp_count },
                { label: "Malware", value: actor.malware_count },
              ].map(s => (
                <div key={s.label} className="bg-slate-800 rounded-lg px-4 py-3">
                  <div className="text-xl font-bold text-sky-400">{s.value}</div>
                  <div className="text-slate-400 text-xs">{s.label}</div>
                </div>
              ))}
            </div>
          </div>
          {actor.description && (
            <p className="mt-4 text-slate-300 text-sm leading-relaxed border-t border-slate-800 pt-4">
              {actor.description.slice(0, 600)}{actor.description.length > 600 ? "…" : ""}
            </p>
          )}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-slate-900 border border-slate-800 rounded-xl p-1 w-fit">
          {(["overview", "indicators", "ttps", "malware"] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-colors ${
                tab === t ? "bg-sky-600 text-white" : "text-slate-400 hover:text-white"
              }`}>{t}</button>
          ))}
        </div>

        {/* Tab content */}
        {tab === "overview" && (
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="font-semibold mb-4 text-white">Targeted Sectors</h3>
              <div className="flex flex-wrap gap-2">
                {actor.targeted_sectors.map(s => (
                  <span key={s} className="bg-slate-800 text-slate-300 px-3 py-1.5 rounded-lg text-sm">{s}</span>
                ))}
                {actor.targeted_sectors.length === 0 && <span className="text-slate-600 text-sm">No data</span>}
              </div>
            </div>
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h3 className="font-semibold mb-4 text-white">Motivation</h3>
              <div className="flex flex-wrap gap-2">
                {actor.motivation.map(m => (
                  <span key={m} className="bg-red-900/30 text-red-300 border border-red-800/40 px-3 py-1.5 rounded-lg text-sm">{m}</span>
                ))}
                {actor.motivation.length === 0 && <span className="text-slate-600 text-sm">No data</span>}
              </div>
            </div>
            {actor.ttps.length > 0 && (
              <div className="col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
                <h3 className="font-semibold mb-4 text-white">ATT&CK Technique Heatmap</h3>
                <AttackHeatmap ttps={actor.ttps} />
              </div>
            )}
            {actor.sources.length > 0 && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <h3 className="font-semibold mb-4 text-white">Sources</h3>
                <ul className="space-y-1">
                  {actor.sources.map((s, i) => (
                    <li key={i} className="text-sm text-slate-300">• {s}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {tab === "indicators" && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <span className="text-sm text-slate-400">{totalIocs} indicators</span>
              <select value={iocType} onChange={e => { setIocType(e.target.value); setIocPage(1); }}
                className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-300 focus:outline-none">
                <option value="">All types</option>
                {["ip", "domain", "url", "md5", "sha1", "sha256", "email", "cve"].map(t => (
                  <option key={t} value={t}>{t.toUpperCase()}</option>
                ))}
              </select>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-left text-xs">
                  <th className="px-4 py-2.5 font-medium">TYPE</th>
                  <th className="px-4 py-2.5 font-medium">VALUE</th>
                  <th className="px-4 py-2.5 font-medium">CONFIDENCE</th>
                  <th className="px-4 py-2.5 font-medium">STATUS</th>
                  <th className="px-4 py-2.5 font-medium">LAST SEEN</th>
                  <th className="px-4 py-2.5 font-medium">SOURCE</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map(ind => <IndicatorRow key={ind.id} ind={ind} />)}
                {iocs.length === 0 && (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-600">No indicators found</td></tr>
                )}
              </tbody>
            </table>
            {totalIocs > 50 && (
              <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between text-sm">
                <span className="text-slate-500">Page {iocPage}</span>
                <div className="flex gap-2">
                  <button onClick={() => setIocPage(p => Math.max(1, p-1))} disabled={iocPage === 1}
                    className="px-3 py-1 bg-slate-800 rounded-lg disabled:opacity-40">← Prev</button>
                  <button onClick={() => setIocPage(p => p+1)} disabled={iocPage * 50 >= totalIocs}
                    className="px-3 py-1 bg-slate-800 rounded-lg disabled:opacity-40">Next →</button>
                </div>
              </div>
            )}
          </div>
        )}

        {tab === "ttps" && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-left text-xs">
                  <th className="px-4 py-3 font-medium">TECHNIQUE ID</th>
                  <th className="px-4 py-3 font-medium">NAME</th>
                  <th className="px-4 py-3 font-medium">TACTIC</th>
                  <th className="px-4 py-3 font-medium">SOURCE</th>
                </tr>
              </thead>
              <tbody>
                {actor.ttps.map(ttp => (
                  <tr key={ttp.technique_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                    <td className="px-4 py-3">
                      <a href={`https://attack.mitre.org/techniques/${ttp.technique_id.replace(".", "/")}`}
                        target="_blank" rel="noopener noreferrer"
                        className="font-mono text-sky-400 hover:text-sky-300 text-xs">{ttp.technique_id} ↗</a>
                    </td>
                    <td className="px-4 py-3 text-slate-200">{ttp.technique_name}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded">{ttp.tactic || "—"}</span>
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">{ttp.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === "malware" && (
          <div className="grid grid-cols-2 gap-4">
            {actor.malware_families.map(m => (
              <div key={m.name} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <div className="flex items-start justify-between mb-2">
                  <span className="font-semibold text-white">{m.name}</span>
                  {m.type && <span className="text-xs bg-red-900/30 text-red-300 border border-red-800/40 px-2 py-0.5 rounded">{m.type}</span>}
                </div>
                {m.aliases.length > 0 && <div className="text-slate-500 text-xs mb-2">AKA: {m.aliases.join(", ")}</div>}
                {m.description && <p className="text-slate-400 text-sm leading-relaxed">{m.description.slice(0, 200)}…</p>}
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
