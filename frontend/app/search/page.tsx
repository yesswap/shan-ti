"use client";
import { useState } from "react";
import Link from "next/link";
import { search as apiSearch, indicators } from "@/lib/api";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<any>(null);
  const [pivot, setPivot] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<"search" | "pivot">("search");

  const handleSearch = async () => {
    if (!query.trim() || query.length < 2) return;
    setLoading(true);
    setResults(null);
    setPivot(null);
    try {
      if (mode === "pivot") {
        const res = await indicators.pivot(query.trim());
        setPivot(res);
      } else {
        const res = await apiSearch(query.trim());
        setResults(res);
      }
    } catch (e: any) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 bg-sky-500 rounded-lg flex items-center justify-center text-white font-bold text-sm">TL</div>
            <span className="font-semibold text-lg">ThreatLens</span>
          </Link>
          <span className="text-slate-600">/</span>
          <span className="text-slate-400">Search</span>
        </div>
        <nav className="flex items-center gap-6 text-sm">
          <Link href="/" className="text-slate-400 hover:text-white">Actors</Link>
          <Link href="/search" className="text-sky-400 font-medium">Search</Link>
        </nav>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-12">
        <h1 className="text-3xl font-bold mb-2">Intelligence Search</h1>
        <p className="text-slate-400 mb-8">Search across actors, IOCs, malware families. Use Pivot mode to trace any indicator to linked actors.</p>

        {/* Mode toggle */}
        <div className="flex gap-1 mb-4 bg-slate-900 border border-slate-800 rounded-xl p-1 w-fit">
          <button onClick={() => setMode("search")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${mode === "search" ? "bg-sky-600 text-white" : "text-slate-400 hover:text-white"}`}>
            🔍 Search
          </button>
          <button onClick={() => setMode("pivot")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${mode === "pivot" ? "bg-sky-600 text-white" : "text-slate-400 hover:text-white"}`}>
            🔄 IOC Pivot
          </button>
        </div>

        <p className="text-slate-500 text-sm mb-3">
          {mode === "search" ? "Search actors, malware names, descriptions" : "Enter an IP, domain, hash, or URL to find linked actors and related IOCs"}
        </p>

        <div className="flex gap-3 mb-8">
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSearch()}
            placeholder={mode === "pivot" ? "185.220.101.47 or malware-domain.ru or abc123..." : "APT28, Lazarus, cobalt, ransomware..."}
            className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-4 py-3 font-mono text-sm focus:outline-none focus:border-sky-500"
          />
          <button onClick={handleSearch} disabled={loading || query.length < 2}
            className="bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white font-semibold px-6 py-3 rounded-xl transition-colors">
            {loading ? "Searching..." : mode === "pivot" ? "Pivot →" : "Search →"}
          </button>
        </div>

        {/* Search results */}
        {results && (
          <div className="space-y-6">
            {results.actors.length > 0 && (
              <div>
                <h2 className="text-lg font-semibold mb-3">Threat Actors ({results.actors.length})</h2>
                <div className="space-y-2">
                  {results.actors.map((a: any) => (
                    <Link key={a.id} href={`/actors/${a.id}`}
                      className="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 hover:border-sky-700 transition-colors">
                      <div>
                        <span className="font-medium text-white">{a.name}</span>
                        {a.mitre_id && <span className="text-slate-500 text-sm ml-3">{a.mitre_id}</span>}
                      </div>
                      {a.nation_state && <span className="text-slate-400 text-sm">{a.nation_state}</span>}
                    </Link>
                  ))}
                </div>
              </div>
            )}

            {results.indicators.length > 0 && (
              <div>
                <h2 className="text-lg font-semibold mb-3">Indicators ({results.indicators.length})</h2>
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                  {results.indicators.map((ind: any) => (
                    <div key={ind.id} className="flex items-center gap-4 px-4 py-3 border-b border-slate-800/50 last:border-0">
                      <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono uppercase w-16 text-center shrink-0">{ind.type}</span>
                      <span className="font-mono text-slate-200 text-sm flex-1 break-all">{ind.value}</span>
                      <span className="text-xs text-slate-500 shrink-0">{ind.actor_name || "Unknown"}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {results.malware.length > 0 && (
              <div>
                <h2 className="text-lg font-semibold mb-3">Malware ({results.malware.length})</h2>
                <div className="grid grid-cols-2 gap-3">
                  {results.malware.map((m: any) => (
                    <div key={m.name} className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                      <div className="font-medium text-white mb-1">{m.name}</div>
                      {m.type && <span className="text-xs text-red-300 bg-red-900/30 px-2 py-0.5 rounded">{m.type}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {results.total_results === 0 && (
              <div className="text-center py-12 text-slate-500">No results for "{results.query}"</div>
            )}
          </div>
        )}

        {/* Pivot results */}
        {pivot && (
          <div className="space-y-6">
            <div className={`border rounded-xl p-6 ${pivot.found ? "bg-slate-900 border-slate-800" : "bg-slate-900 border-slate-800"}`}>
              <div className="flex items-center gap-3 mb-4">
                <span className={`w-3 h-3 rounded-full ${pivot.found ? "bg-emerald-400" : "bg-slate-600"}`} />
                <h2 className="text-lg font-semibold">{pivot.found ? "Indicator found" : "Not in database"}</h2>
              </div>
              <div className="font-mono text-sky-300 bg-slate-800 px-4 py-2 rounded-lg text-sm mb-4 break-all">{pivot.value}</div>

              {pivot.found && (
                <>
                  <div className="grid grid-cols-3 gap-4 mb-6 text-sm">
                    <div><span className="text-slate-500">Types: </span><span>{pivot.indicator_types.join(", ")}</span></div>
                    <div><span className="text-slate-500">Corroborations: </span><span className="text-sky-400 font-semibold">{pivot.corroboration_count}</span></div>
                    <div><span className="text-slate-500">Sources: </span><span>{pivot.sources.join(", ")}</span></div>
                    <div><span className="text-slate-500">First seen: </span><span>{pivot.first_seen ? new Date(pivot.first_seen).toLocaleDateString() : "—"}</span></div>
                    <div><span className="text-slate-500">Last seen: </span><span>{pivot.last_seen ? new Date(pivot.last_seen).toLocaleDateString() : "—"}</span></div>
                  </div>

                  {pivot.actors.length > 0 && (
                    <div className="mb-6">
                      <h3 className="font-medium mb-3 text-slate-300">Linked Actors</h3>
                      <div className="space-y-2">
                        {pivot.actors.map((a: any) => (
                          <Link key={a.id} href={`/actors/${a.id}`}
                            className="flex items-center justify-between bg-slate-800 rounded-lg px-4 py-2.5 hover:bg-slate-700 transition-colors">
                            <span className="font-medium">{a.name}</span>
                            <div className="flex items-center gap-3 text-sm text-slate-400">
                              {a.nation_state && <span>{a.nation_state}</span>}
                              {a.mitre_id && <span className="text-sky-400">{a.mitre_id}</span>}
                            </div>
                          </Link>
                        ))}
                      </div>
                    </div>
                  )}

                  {pivot.related_indicators.length > 0 && (
                    <div>
                      <h3 className="font-medium mb-3 text-slate-300">Related Indicators (same actors)</h3>
                      <div className="bg-slate-800 rounded-xl overflow-hidden">
                        {pivot.related_indicators.slice(0, 10).map((ind: any, i: number) => (
                          <div key={i} className="flex items-center gap-3 px-4 py-2.5 border-b border-slate-700/50 last:border-0">
                            <span className="text-xs bg-slate-700 text-slate-400 px-2 py-0.5 rounded font-mono uppercase w-14 text-center shrink-0">{ind.type}</span>
                            <span className="font-mono text-slate-300 text-xs flex-1 break-all">{ind.value}</span>
                            <span className="text-xs text-slate-500 shrink-0">{ind.confidence}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
