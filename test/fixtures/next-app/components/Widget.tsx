'use client';
export function Widget() {
  window.addEventListener('message', (e) => {
    document.getElementById('out')!.innerHTML = e.data.html;
  });
  const q = new URLSearchParams(window.location.search).get('next');
  if (q) window.location.href = q;
  return null;
}
