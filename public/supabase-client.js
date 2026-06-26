/* ════════════════════════════════════════════════════
   CheckVibe — Supabase client (auth + database)
   ════════════════════════════════════════════════════
   PASTE YOUR VALUES BELOW. They are the PUBLIC (anon) key +
   project URL from Supabase → Project Settings → API.

   DO NOT paste your "service role" key here — that one bypasses
   Row Level Security and must never reach the browser.

   Until you fill these in, the site keeps working as a free
   scanner (login/save/dashboard features simply no-op).
   ════════════════════════════════════════════════════ */

// Load the SDK from the CDN (it exposes window.supabase)
// The actual createClient call below handles missing-SDK gracefully.

const SUPABASE_URL  = 'https://YOUR-PROJECT.supabase.co';  // ← paste Project URL
const SUPABASE_ANON = 'YOUR-ANON-PUBLIC-KEY';              // ← paste anon/publishable key

// Expose a single global `sb` to all pages.
// `sb` is null when Supabase isn't configured, so feature code can feature-detect.
window.sb = null;

(function initSupabase() {
  const hasSDK = typeof window.supabase !== 'undefined' && window.supabase.createClient;
  const configured = SUPABASE_URL.startsWith('https://') && SUPABASE_ANON.length > 20;

  if (!hasSDK) {
    console.info('[CheckVibe] Supabase SDK not loaded — running in scanner-only mode.');
    return;
  }
  if (!configured) {
    console.info('[CheckVibe] Supabase not configured — running in scanner-only mode. Paste your values in supabase-client.js to enable accounts & history.');
    return;
  }

  try {
    window.sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
    });
    console.info('[CheckVibe] Supabase connected.');
  } catch (e) {
    console.warn('[CheckVibe] Supabase init failed:', e.message);
  }
})();
