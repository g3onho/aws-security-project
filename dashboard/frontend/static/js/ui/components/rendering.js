// Patch existing nodes so refreshes retain focus, scroll containers and Chart canvases.
const key = node => node.nodeType === 1 ? node.id || node.getAttribute('data-key') || '' : '';
const matches = (a, b) => a.nodeType === b.nodeType && a.nodeName === b.nodeName && key(a) === key(b);

function patchNode(current, next) {
  if (current.nodeType !== 1) {
    if (current.nodeValue !== next.nodeValue) current.nodeValue = next.nodeValue;
    return;
  }
  // A panel's own request owns its contents and loading state, not the parent shell.
  if (current.hasAttribute('data-async-panel') && next.hasAttribute('data-async-panel')) return;
  const preserve = name => (current.tagName === 'CANVAS' && ['width', 'height', 'style'].includes(name)) ||
    (current.tagName === 'DETAILS' && name === 'open');
  for (const {name} of [...current.attributes]) {
    if (!preserve(name) && !next.hasAttribute(name)) current.removeAttribute(name);
  }
  for (const {name, value} of next.attributes) {
    if (!preserve(name) && current.getAttribute(name) !== value) current.setAttribute(name, value);
  }
  patchChildren(current, next);
  if (current.tagName === 'INPUT') {
    current.checked = next.checked;
    if (current.value !== next.value) current.value = next.value;
  } else if (['SELECT', 'TEXTAREA'].includes(current.tagName) && current.value !== next.value) {
    current.value = next.value;
  }
}

function patchChildren(parent, next) {
  let cursor = parent.firstChild;
  for (const desired of [...next.childNodes]) {
    let current = cursor;
    if (!current || !matches(current, desired)) {
      current = key(desired) ? [...parent.childNodes].find(node => matches(node, desired)) : null;
      if (current) parent.insertBefore(current, cursor);
      else {
        parent.insertBefore(desired.cloneNode(true), cursor);
        continue;
      }
    }
    patchNode(current, desired);
    cursor = current.nextSibling;
  }
  while (cursor) {
    const nextSibling = cursor.nextSibling;
    cursor.remove();
    cursor = nextSibling;
  }
}

export function patchMarkup(container, html) {
  const template = container.ownerDocument.createElement('template');
  template.innerHTML = html;
  patchChildren(container, template.content);
}
