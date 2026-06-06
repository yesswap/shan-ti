"use client";
import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { actors, stats, ActorSummary } from "@/lib/api";

const NATION_FLAGS: Record<string, string> = {
  China: "🇨🇳", Russia: "🇷🇺", "North Korea": "🇰🇵", Iran: "🇮🇷",
  Vietnam: "🇻🇳", Pakistan: "🇵🇰", India: "🇮🇳", Turkey: "🇹🇷",
  Israel: "🇮🇱", USA: "🇺🇸",
};

const CONFIDENCE_COLOR: Record<string, string> = {
  confirmed: "text-emerald-400 bg-emerald-400/10",
  high: "text-green-400 bg-green-400/10",
  medium: "text-yellow-400 bg-yellow-400/10",
  low: "text-orange-400 bg-orange-400/10",
  unknown: "text-slate-400 bg-slate-400/10",
};

function ConfidenceBadge({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const label = score >= 0.85 ? "confirmed" : score >= 0.7 ? "high" : score >= 0.5 ? "medium" : "low";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${CONFIDENCE_COLOR[label]}`}>
      {pct}%
    </span>
  );
}

export default function ActorRegistryPage() {
  const [data, setData] = useState<{ total: number; results: ActorSummary[] } | null>(null);
  const [statsData, setStatsData] = useState<any>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [nation, setNation] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await actors.list({ page, page_size: 20, search: search || undefined, nation_state: nation || undefined });
      setData(res);
    } catch (e: any) {
      if (e.status === 401) setError("API key required. Register at /register.");
      else setError("Failed to load actors.");
    } finally {
      setLoading(false);
    }
  }, [page, search, nation]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    stats().then(setStatsData).catch(() => {});
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-sky-500 rounded-lg flex items-center justify-center text-white font-bold text-sm">TL</div>
          <span className="font-semibold text-lg">ThreatLens</span>
          <span className="text-slate-500 text-sm">Threat Actor Intelligence</span>
        </div>
        <nav className="flex items-center gap-6 text-sm">
          <Link href="/" className="text-sky-400 font-medium">Actors</Link>
          <Link href="/indicators" className="text-slate-400 hover:text-white">Indicators</Link>
          <Link href="/search" className="text-slate-400 hover:text-white">Search</Link>
          <Link href="/register" className="bg-sky-600 hover:bg-sky-500 px-3 py-1.5 rounded-lg text-white font-medium">
            Get API Key
          </Link>
        </nav>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Stats bar */}
        {statsData && (
          <div className="grid grid-cols-4 gap-4 mb-8">
            {[
              { label: "Threat Actors", value: statsData.actors, icon: "👤" },
              { label: "Fresh IOCs", value: statsData.indicators?.fresh?.toLocaleString(), icon: "🎯" },
              { label: "ATT&CK TTPs", value: statsData.ttps?.toLocaleString(), icon: "🔧" },
              { label: "Malware Families", value: statsData.malware_families, icon: "🦠" },
            ].map(s => (
              <div key={s.label} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <div className="text-2xl mb-1">{s.icon}</div>
                <div className="text-2xl font-bold text-white">{s.value ?? "—"}</div>
                <div className="text-slate-400 text-sm">{s.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Filters */}
        <div className="flex gap-3 mb-6">
          <input
            type="text"
            placeholder="Search actors, descriptions..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-sky-500"
          />
          <select
            value={nation}
            onChange={e => { setNation(e.target.value); setPage(1); }}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-sky-500 min-w-[160px]"
          >
            <option value="">All Nations</option>
            {["China", "Russia", "North Korea", "Iran", "Vietnam", "Pakistan", "India"].map(n => (
              <option key={n} value={n}>{NATION_FLAGS[n]} {n}</option>
            ))}
          </select>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-6 text-red-400 text-sm">
            {error}{" "}
            {error.includes("API key") && (
              <Link href="/register" className="underline text-red-300">Register here →</Link>
            )}
          </div>
        )}

        {/* Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-left">
                <th className="px-4 py-3 font-medium">Actor</th>
                <th className="px-4 py-3 font-medium">Nation</th>
                <th className="px-4 py-3 font-medium">Sectors</th>
                <th className="px-4 py-3 font-medium text-right">IOCs</th>
                <th className="px-4 py-3 font-medium text-right">TTPs</th>
                <th className="px-4 py-3 font-medium text-right">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} className="border-b border-slate-800/50">
                    <td colSpan={6} className="px-4 py-3">
                      <div className="h-4 bg-slate-800 rounded animate-pulse w-full" />
                    </td>
                  </tr>
                ))
              ) : data?.results.map(actor => (
                <tr key={actor.id} className="border-b border-slate-800/50 hover:bg-slate-800/50 transition-colors">
                  <td className="px-4 py-3">
                    <Link href={`/actors/${actor.id}`} className="group">
                      <div className="font-medium text-white group-hover:text-sky-400 transition-colors">{actor.name}</div>
                      {actor.mitre_id && <div className="text-slate-500 text-xs mt-0.5">{actor.mitre_id}</div>}
                      {actor.aliases.length > 0 && (
                        <div className="text-slate-500 text-xs mt-0.5">{actor.aliases.slice(0, 2).join(", ")}</div>
                      )}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    {actor.nation_state ? (
                      <span className="text-slate-300">
                        {NATION_FLAGS[actor.nation_state] || ""} {actor.nation_state}
                      </span>
                    ) : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {actor.targeted_sectors.slice(0, 3).map(s => (
                        <span key={s} className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full">{s}</span>
                      ))}
                      {actor.targeted_sectors.length > 3 && (
                        <span className="text-xs text-slate-600">+{actor.targeted_sectors.length - 3}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className={actor.indicator_count > 0 ? "text-sky-400 font-medium" : "text-slate-600"}>
                      {actor.indicator_count.toLocaleString()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className="text-slate-300">{actor.ttp_count}</span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <ConfidenceBadge score={actor.overall_confidence} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          {data && data.total > 20 && (
            <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between text-sm">
              <span className="text-slate-400">{data.total} actors total</span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 bg-slate-800 rounded-lg disabled:opacity-40 hover:bg-slate-700"
                >← Prev</button>
                <span className="px-3 py-1 text-slate-400">Page {page}</span>
                <button
                  onClick={() => setPage(p => p + 1)}
                  disabled={page * 20 >= data.total}
                  className="px-3 py-1 bg-slate-800 rounded-lg disabled:opacity-40 hover:bg-slate-700"
                >Next →</button>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
