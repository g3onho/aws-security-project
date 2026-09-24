// Keep visual state, keyboard dismissal and accessibility state in one place.
export function createNotificationPopover({button, panel}) {
  const document = button.ownerDocument;
  const contains = target => button.contains(target) || panel.contains(target);
  function setOpen(open, restoreFocus = false) {
    panel.hidden = !open;
    button.setAttribute('aria-expanded', String(open));
    if (restoreFocus) button.focus();
  }
  const toggle = () => setOpen(panel.hidden);
  const outside = event => { if (!panel.hidden && !contains(event.target)) setOpen(false); };
  const escape = event => {
    if (event.key === 'Escape' && !panel.hidden) {
      event.preventDefault();setOpen(false, true);
    }
  };
  button.addEventListener('click', toggle);
  document.addEventListener('pointerdown', outside);
  document.addEventListener('click', outside);
  document.addEventListener('focusin', outside);
  document.addEventListener('keydown', escape);
  setOpen(false);
  return {
    close: (restoreFocus = false) => setOpen(false, restoreFocus),
    destroy() {
      button.removeEventListener('click', toggle);
      document.removeEventListener('pointerdown', outside);
      document.removeEventListener('click', outside);
      document.removeEventListener('focusin', outside);
      document.removeEventListener('keydown', escape);
    },
  };
}
