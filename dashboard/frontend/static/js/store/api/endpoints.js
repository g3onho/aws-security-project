// API 경로는 여기서만 정한다(설계 2.1-2: UI는 URL을 모른다).
export const endpoints=Object.freeze({
 session:'/api/auth/session',logout:'/api/auth/logout',
 events:'/api/events',summary:'/api/summary',metrics:'/api/metrics',infra:'/api/infra/status',
 vulnerabilities:'/api/vulnerabilities',history:'/api/history',health:'/health',
 drillsCatalog:'/api/drills/catalog',drills:'/api/drills',
 drillWebScanStart:'/api/drills/web-scan/start',
 drillWebScanStatus:runId=>`/api/drills/web-scan/${encodeURIComponent(runId)}/status`,
});
