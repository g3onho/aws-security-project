// Point-in-polygon sanity checks for v2.2's country-highlight feature (static/js/map.js: findCountryIndex).
// Node-only, no browser required: run with `node tests/v2.2-country-highlight-check.mjs`.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { findCountryIndex } from '../static/js/map.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const raw = readFileSync(join(__dirname, '../static/data/countries.geojson'), 'utf-8');
const data = JSON.parse(raw);
// mirror app.js's loadMap(): Antarctica is filtered out before use.
const features = data.features.filter(f => f.properties.ADMIN !== 'Antarctica');

function expectCountry(lon, lat, expectedAdmin, label) {
  const idx = findCountryIndex(lon, lat, features);
  if (idx === -1) throw new Error(`FAIL ${label}: expected "${expectedAdmin}", got no match (-1)`);
  const got = features[idx].properties.ADMIN;
  if (got !== expectedAdmin) throw new Error(`FAIL ${label}: expected "${expectedAdmin}", got "${got}"`);
  console.log(`ok ${label}: -> ${got} (index ${idx})`);
}

function expectNoMatch(lon, lat, label) {
  const idx = findCountryIndex(lon, lat, features);
  if (idx !== -1) throw new Error(`FAIL ${label}: expected no match, got index ${idx} ("${features[idx].properties.ADMIN}")`);
  console.log(`ok ${label}: -> no match (-1), as expected`);
}

// AWS regions (from data.js), one assertion per region.
expectCountry(126.978, 37.566, 'South Korea', 'ap-northeast-2 Seoul');
expectCountry(139.69, 35.68, 'Japan', 'ap-northeast-1 Tokyo');
expectCountry(8.68, 50.11, 'Germany', 'eu-central-1 Frankfurt');
expectCountry(-77.49, 38.75, 'United States of America', 'us-east-1 Virginia');
expectCountry(-82.99, 39.96, 'United States of America', 'us-east-2 Ohio');
expectCountry(-121.89, 37.34, 'United States of America', 'us-west-1 California');
expectCountry(-122.68, 45.52, 'United States of America', 'us-west-2 Oregon');
expectCountry(72.88, 19.08, 'India', 'ap-south-1 Mumbai');
expectCountry(135.5, 34.69, 'Japan', 'ap-northeast-3 Osaka');
expectCountry(151.21, -33.87, 'Australia', 'ap-southeast-2 Sydney');
expectCountry(-73.57, 45.5, 'Canada', 'ca-central-1 Canada Central');
expectCountry(-6.26, 53.35, 'Ireland', 'eu-west-1 Ireland');
expectCountry(-0.13, 51.51, 'United Kingdom', 'eu-west-2 London');
expectCountry(2.35, 48.86, 'France', 'eu-west-3 Paris');
expectCountry(18.07, 59.33, 'Sweden', 'eu-north-1 Stockholm');
expectCountry(-46.63, -23.55, 'Brazil', 'sa-east-1 Sao Paulo');

// v2.2 follow-up fix: the base 110m Natural-Earth-style countries.geojson omitted Singapore
// entirely (too small for that resolution), and its simplified Malaysia polygon happened to
// cover Singapore's coordinates -- so ap-southeast-1 used to highlight Malaysia instead. A real
// Singapore polygon (from datasets/geo-countries, OSM-derived) was added as the FIRST feature in
// the array so it wins the point-in-polygon test ahead of Malaysia's coarser shape.
expectCountry(103.82, 1.35, 'Singapore', 'ap-southeast-1 Singapore (now resolves correctly)');

// The fix must not disturb Malaysia itself: a point well inside mainland Malaysia (away from the
// Singapore Strait) should still resolve to Malaysia, not accidentally to the new Singapore
// polygon or anything else.
expectCountry(101.69, 3.14, 'Malaysia', 'mainland Malaysia (Kuala Lumpur) unaffected by the fix');

// Multi-region country check: the US (4 regions) and Japan (2 regions) must both resolve to a
// SINGLE, consistent country index per country -- confirming no special-casing is needed for
// countries with more than one AWS region, per the user's explicit decision to let this be
// handled generically.
{
  const usIdx = new Set([
    findCountryIndex(-77.49, 38.75, features),
    findCountryIndex(-82.99, 39.96, features),
    findCountryIndex(-121.89, 37.34, features),
    findCountryIndex(-122.68, 45.52, features),
  ]);
  if (usIdx.size !== 1 || usIdx.has(-1)) throw new Error(`FAIL US multi-region consistency: got indices ${[...usIdx]}`);
  console.log(`ok US multi-region consistency: all 4 regions -> single index ${[...usIdx][0]}`);

  const jpIdx = new Set([
    findCountryIndex(139.69, 35.68, features),
    findCountryIndex(135.5, 34.69, features),
  ]);
  if (jpIdx.size !== 1 || jpIdx.has(-1)) throw new Error(`FAIL Japan multi-region consistency: got indices ${[...jpIdx]}`);
  console.log(`ok Japan multi-region consistency: both regions -> single index ${[...jpIdx][0]}`);
}

// Threat-actor origin countries (from data.js) resolve too, since the same lookup could be
// reused for actor markers if ever needed -- not currently wired up, but worth confirming the
// underlying data supports it.
expectCountry(125.75, 39.02, 'North Korea', 'threat actor: North Korea (Pyongyang)');
expectCountry(116.41, 39.90, 'China', 'threat actor: China (Beijing)');
expectCountry(37.62, 55.75, 'Russia', 'threat actor: Russia (Moscow)');
expectCountry(51.39, 35.69, 'Iran', 'threat actor: Iran (Tehran)');

console.log('\nAll v2.2 country-highlight checks passed.');
