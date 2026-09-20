// Sanity checks for v2.1 data (threatActors) and the great-circle attack-line rendering.
// Node-only, no browser required: run with `node tests/v2.1-data-check.mjs`.
import {regions, threatActors, createEvents} from '../static/js/data.js';
import {connectionMarkup, DEFAULT_ROTATION, DEFAULT_ZOOM} from '../static/js/map.js';

function assert(cond, label) {
  if (!cond) throw new Error(`FAIL: ${label}`);
  console.log(`ok ${label}`);
}

assert(threatActors.length === 8, 'threatActors has 8 countries');
assert(threatActors.every(a => /^[A-Za-z() ]+$/.test(a.country)), 'every threat actor country name is in English');
assert(threatActors.every(a => a.groups.length && a.purpose && a.targets.length && a.tactics.length), 'every threat actor has groups/purpose/targets/tactics');

// No threat-actor origin sits on top of (or within 0.01 degrees of) any AWS region marker —
// this was the exact bug being fixed (origins colliding with the newly-added Paris/Sydney regions).
for (const a of threatActors) {
  for (const r of regions) {
    if (r.lon === undefined) continue;
    const d = Math.hypot(a.lon - r.lon, a.lat - r.lat);
    assert(d > 0.01, `threat actor ${a.country} does not sit exactly on region ${r.id} (distance ${d.toFixed(2)})`);
  }
}

const events = createEvents();
assert(events.length > 0, 'createEvents produced events');
const attacks = events.filter(e => e.sourceLocation);
assert(attacks.length > 0, 'some events have a resolved sourceLocation');
assert(attacks.every(e => threatActors.some(a => a.id === e.sourceLocation.actorId)), 'every located attack event maps to a known threatActor id');
assert(attacks.every(e => e.sourceLocation.country), 'every located attack event carries a country label');

// Every geo-located region (all regions except the coordinate-less 'global' one) is attacked by
// at least 2 distinct countries, per the "한 리전당 최소 두개 이상" requirement.
for (const r of regions) {
  if (r.lon === undefined) continue;
  const countries = new Set(attacks.filter(e => e.region === r.id).map(e => e.sourceLocation.country));
  assert(countries.size >= 2, `region ${r.id} has attacks from >=2 distinct countries (has ${countries.size}: ${[...countries].join(', ')})`);
}

// Render a great-circle attack line end-to-end for one located event and confirm it produces a
// non-empty, well-formed SVG path when the globe is centered on its own region (fully visible).
const sample = attacks[0];
const r = regions.find(rr => rr.id === sample.region);
const rotation = [r.lon, r.lat];
const markup = connectionMarkup([sample], regions, s => s, rotation, DEFAULT_ZOOM);
assert(markup.includes('<path class="attack-line" d="M'), 'connectionMarkup renders a moveto-started path when centered on the event region');
assert(markup.includes(sample.sourceIp), 'rendered markup includes the source IP');

console.log('ALL DATA/ATTACK-LINE CHECKS PASSED');
