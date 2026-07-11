import './style.css';
import { bootstrap } from './app';

const root = document.querySelector<HTMLDivElement>('#app');
if (!root) throw new Error('Missing app root');

await bootstrap(root);

const ICON_LIGHT = '☀';
const ICON_DARK = '☾';

function applyToggleIcon(button: HTMLButtonElement): void {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  button.textContent = isLight ? ICON_DARK : ICON_LIGHT;
  button.setAttribute('aria-label', isLight ? 'Switch to dark mode' : 'Switch to light mode');
}

const toggleButton = document.querySelector<HTMLButtonElement>('#themeToggle');
if (toggleButton) {
  applyToggleIcon(toggleButton);
  toggleButton.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const next = isLight ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    applyToggleIcon(toggleButton);
  });
}
