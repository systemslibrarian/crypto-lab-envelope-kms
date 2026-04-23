import './style.css';
import { bootstrap } from './app';

const root = document.querySelector<HTMLDivElement>('#app');
if (!root) throw new Error('Missing app root');

await bootstrap(root);

const ICON_LIGHT = '☀';
const ICON_DARK = '☾';

function applyToggleIcon(button: HTMLButtonElement): void {
  const isLight = document.documentElement.classList.contains('light');
  button.textContent = isLight ? ICON_DARK : ICON_LIGHT;
  button.setAttribute(
    'aria-label',
    isLight ? 'Switch to dark mode' : 'Switch to light mode',
  );
}

const toggleButton = document.querySelector<HTMLButtonElement>('#themeToggle');
if (toggleButton) {
  applyToggleIcon(toggleButton);
  toggleButton.addEventListener('click', () => {
    const next = document.documentElement.classList.toggle('light');
    localStorage.setItem('theme', next ? 'light' : 'dark');
    applyToggleIcon(toggleButton);
  });
}
