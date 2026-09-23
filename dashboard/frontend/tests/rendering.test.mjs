import test from 'node:test';
import assert from 'node:assert/strict';
import {JSDOM} from './dom-test-support.mjs';
import {patchMarkup} from '../static/js/rendering.js';

function container(html) {
  const dom = new JSDOM(`<main>${html}</main>`);
  return {dom, box: dom.window.document.querySelector('main')};
}

test('refresh preserves stable nodes, canvas ownership and scroll position', () => {
  const {box} = container('<section id="panel"><h2>Before</h2><div class="scroll"><canvas id="chart"></canvas></div></section>');
  const section = box.firstElementChild;
  const heading = box.querySelector('h2');
  const scroll = box.querySelector('.scroll');
  const canvas = box.querySelector('canvas');
  canvas.width = 900; canvas.height = 400; canvas.style.width = '450px';
  canvas.chartInstance = {id: 7}; scroll.scrollTop = 123;
  patchMarkup(box, '<section id="panel"><h2>After</h2><div class="scroll"><canvas id="chart" aria-label="Updated"></canvas></div></section>');
  assert.equal(box.firstElementChild, section);
  assert.equal(box.querySelector('h2'), heading);
  assert.equal(heading.textContent, 'After');
  assert.equal(box.querySelector('canvas'), canvas);
  assert.equal(canvas.chartInstance.id, 7);
  assert.equal(canvas.width, 900); assert.equal(canvas.height, 400);
  assert.equal(canvas.style.width, '450px');
  assert.equal(canvas.getAttribute('aria-label'), 'Updated');
  assert.equal(scroll.scrollTop, 123);
});

test('id and data-key items reorder without exchanging node identities', () => {
  const {box} = container('<div data-key="a">A</div><div data-key="b">B</div><p id="c">C</p>');
  const [a, b, c] = box.children;
  patchMarkup(box, '<p id="c">C2</p><div data-key="b">B2</div><div data-key="a">A2</div>');
  assert.deepEqual([...box.children], [c, b, a]);
  assert.deepEqual([...box.children].map(node => node.textContent), ['C2', 'B2', 'A2']);
  patchMarkup(box, '<span data-key="b">new tag</span><div data-key="a">A3</div>');
  assert.equal(box.children.length, 2);
  assert.equal(box.lastElementChild, a);
  assert.notEqual(box.firstElementChild, b);
  assert.equal(box.firstElementChild.tagName, 'SPAN');
  assert.equal(c.isConnected, false);
});

test('rendered form values and checked state override dirty properties without replacing controls', () => {
  const {box, dom} = container('<input id="name" value="initial"><input id="flag" type="checkbox"><select id="choice"><option value="a">A</option><option value="b">B</option></select><textarea id="note">initial</textarea>');
  const input = box.querySelector('#name');
  const checkbox = box.querySelector('#flag');
  const select = box.querySelector('#choice');
  const textarea = box.querySelector('#note');
  input.value = 'user edit'; input.focus(); checkbox.checked = true;
  select.value = 'b'; textarea.value = 'user edit';
  patchMarkup(box, '<input id="name" value="server"><input id="flag" type="checkbox"><select id="choice"><option value="a" selected>A</option><option value="b">B</option></select><textarea id="note">server note</textarea>');
  assert.equal(box.querySelector('#name'), input);
  assert.equal(dom.window.document.activeElement, input);
  assert.equal(input.value, 'server');
  assert.equal(checkbox.checked, false);
  assert.equal(select.value, 'a');
  assert.equal(textarea.value, 'server note');
});

test('expanded and collapsed details remain in the state chosen by the user', () => {
  const {box} = container('<details id="expanded"><summary>A</summary><p>before</p></details><details id="closed" open><summary>B</summary></details>');
  const expanded = box.querySelector('#expanded');
  const closed = box.querySelector('#closed');
  expanded.open = true; closed.open = false;
  patchMarkup(box, '<details id="expanded"><summary>A updated</summary><p>after</p></details><details id="closed" open><summary>B updated</summary></details>');
  assert.equal(expanded.open, true);
  assert.equal(closed.open, false);
  assert.equal(expanded.querySelector('p').textContent, 'after');
});

test('parent skeleton refresh preserves async panel content and its own busy state', () => {
  const {box} = container('<section><div id="async" data-async-panel aria-busy="true"><table><tbody><tr><td>Loaded</td></tr></tbody></table></div></section>');
  const panel = box.querySelector('#async');
  const table = panel.firstElementChild;
  patchMarkup(box, '<section><div id="async" data-async-panel class="load-state">Loading…</div></section>');
  assert.equal(box.querySelector('#async'), panel);
  assert.equal(panel.firstElementChild, table);
  assert.equal(panel.textContent, 'Loaded');
  assert.equal(panel.getAttribute('aria-busy'), 'true');
  patchMarkup(panel, '<p>New panel result</p>');
  assert.equal(panel.textContent, 'New panel result');
  patchMarkup(box, '<section><p>Another view</p></section>');
  assert.equal(panel.isConnected, false);
});
