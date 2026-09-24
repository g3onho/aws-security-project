import test from 'node:test';
import assert from 'node:assert/strict';
import {vulnerabilityCsv} from '../static/js/ui/components/downloads.js';

test('CVE export includes all filtered rows, quotes data and neutralizes spreadsheet formulas',()=>{
  const data={items:[
    {resource:'image-a',severity:'HIGH',cveId:'CVE-2026-1',package:'pkg,"quoted"',cvss:0},
    {resource:'image-b',severity:'LOW',cveId:'CVE-2026-2',package:'=HYPERLINK("test")'},
  ]};
  const csv=vulnerabilityCsv(data);
  assert.ok(csv.startsWith('\uFEFF"심각도"'));
  assert.ok(csv.includes('"0","CVE-2026-1","pkg,""quoted"""'));
  assert.ok(csv.includes('"\'=HYPERLINK(""test"")"'));
  const filtered=vulnerabilityCsv(data,'image-b');
  assert.equal(filtered.includes('CVE-2026-1'),false);
  assert.ok(filtered.includes('CVE-2026-2'));
});
