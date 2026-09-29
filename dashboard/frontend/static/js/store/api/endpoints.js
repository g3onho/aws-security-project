// API 경로는 여기서만 정한다(설계 2.1-2: UI는 URL을 모른다).
export const endpoints=Object.freeze({
 session:'/api/auth/session',logout:'/api/auth/logout',
 events:'/api/events',summary:'/api/summary',metrics:'/api/metrics',infra:'/api/infra/status',
 vulnerabilities:'/api/vulnerabilities',history:'/api/history',health:'/health',
 drillsCatalog:'/api/drills/catalog',drills:'/api/drills',
 drillWebScanStart:'/api/drills/web-scan/start',
 drillWebScanStatus:runId=>`/api/drills/web-scan/${encodeURIComponent(runId)}/status`,
 drillRunAllStart:'/api/drills/run-all/start',
 drillRunAllStatus:runId=>`/api/drills/run-all/${encodeURIComponent(runId)}/status`,
 // 허니팟 화면·차단 IP 관리(v25)
 honeypotStatus:'/api/honeypot/status',honeypotSessions:'/api/honeypot/sessions',honeypotStats:'/api/honeypot/stats',
 honeypotTimeline:'/api/honeypot/timeline',
 honeypotSession:id=>`/api/honeypot/sessions/${encodeURIComponent(id)}`,
 blocklist:'/api/blocklist',
 blocklistRelease:ip=>`/api/blocklist/${encodeURIComponent(ip)}/release`,
 blocklistPatch:ip=>`/api/blocklist/${encodeURIComponent(ip)}`,
});
