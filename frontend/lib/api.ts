const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

function getKey(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("tl_api_key");
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const key = getKey();
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(key ? { "X-API-Key": key } : {}),
      ...opts.headers,
    },
  });

  const data = await res.json();
  if (!res.ok) {
    throw { status: res.status, ...data };
  }
  return data as T;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export const auth = {
  register: (email: string, name?: string) =>
    apiFetch<{ message: string; email: string }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, name }),
    }),

  me: () =>
    apiFetch<{
      email: string;
      name: string | null;
      plan: string;
      is_verified: boolean;
      created_at: string;
      api_keys: { id: number; prefix: string; name: string; last_used: string | null }[];
      usage_today: number;
      usage_this_minute: number;
      rate_limits: { per_minute: number; per_day: number };
    }>("/auth/me"),

  revokeKey: (keyId: number) =>
    apiFetch<{ message: string }>(`/auth/keys/${keyId}`, { method: "DELETE" }),

  createKey: (name: string) =>
    apiFetch<{ message: string; api_key: string; key_prefix: string; name: string }>("/auth/keys", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),
};

// ─── Actors ───────────────────────────────────────────────────────────────────

export interface ActorSummary {
  id: number;
  name: string;
  mitre_id: string | null;
  aliases: string[];
  nation_state: string | null;
  motivation: string[];
  active_status: string;
  targeted_sectors: string[];
  overall_confidence: number;
  indicator_count: number;
  ttp_count: number;
  malware_count: number;
  updated_at: string | null;
}

export interface ActorDetail extends ActorSummary {
  sponsor: string | null;
  active_since: string | null;
  targeted_regions: string[];
  description: string | null;
  sources: string[];
  source_urls: string[];
  ttps: TTP[];
  malware_families: Malware[];
  campaign_count: number;
}

export interface TTP {
  technique_id: string;
  technique_name: string;
  tactic: string | null;
  description: string | null;
  source: string | null;
}

export interface Malware {
  name: string;
  aliases: string[];
  type: string | null;
  description: string | null;
}

export interface Indicator {
  id: number;
  type: string;
  value: string;
  confidence: string;
  confidence_score: number;
  status: string;
  tlp_level: string;
  first_seen: string | null;
  last_seen: string | null;
  expires_at: string | null;
  source: string | null;
  source_url: string | null;
  corroboration_count: number;
  tags: string[];
  actor_name: string | null;
}

export interface Paginated<T> {
  total: number;
  page: number;
  page_size: number;
  results: T[];
}

export const actors = {
  list: (params?: {
    page?: number;
    page_size?: number;
    nation_state?: string;
    active_status?: string;
    sector?: string;
    search?: string;
  }) => {
    const qs = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([k, v]) => v !== undefined && qs.set(k, String(v)));
    }
    return apiFetch<Paginated<ActorSummary>>(`/actors?${qs}`);
  },

  get: (id: number) => apiFetch<ActorDetail>(`/actors/${id}`),

  indicators: (id: number, params?: { page?: number; ioc_type?: string; status?: string; include_expired?: boolean }) => {
    const qs = new URLSearchParams();
    if (params) Object.entries(params).forEach(([k, v]) => v !== undefined && qs.set(k, String(v)));
    return apiFetch<Paginated<Indicator>>(`/actors/${id}/indicators?${qs}`);
  },

  ttps: (id: number) => apiFetch<TTP[]>(`/actors/${id}/ttps`),
};

export const indicators = {
  list: (params?: { page?: number; ioc_type?: string; status?: string; include_expired?: boolean }) => {
    const qs = new URLSearchParams();
    if (params) Object.entries(params).forEach(([k, v]) => v !== undefined && qs.set(k, String(v)));
    return apiFetch<Paginated<Indicator>>(`/indicators?${qs}`);
  },

  pivot: (value: string) => apiFetch<{
    value: string;
    found: boolean;
    indicator_types: string[];
    actors: { id: number; name: string; nation_state: string | null; mitre_id: string | null }[];
    corroboration_count: number;
    first_seen: string | null;
    last_seen: string | null;
    sources: string[];
    related_indicators: { type: string; value: string; confidence: string; status: string }[];
  }>(`/indicators/pivot/${encodeURIComponent(value)}`),
};

export const search = (q: string) =>
  apiFetch<{
    query: string;
    actors: { id: number; name: string; nation_state: string | null; mitre_id: string | null }[];
    indicators: Indicator[];
    malware: { name: string; type: string | null; description: string | null }[];
    total_results: number;
  }>(`/search?q=${encodeURIComponent(q)}`);

export const stats = () =>
  apiFetch<{
    actors: number;
    indicators: { total: number; fresh: number };
    ttps: number;
    malware_families: number;
    actors_by_nation: { nation: string; count: number }[];
    indicators_by_type: { type: string; count: number }[];
  }>("/stats");
