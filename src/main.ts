import './style.css';
import { bootstrap } from './app';

const root = document.querySelector<HTMLDivElement>('#app');
if (!root) throw new Error('Missing app root');

await bootstrap(root);

const toggle = () => {
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!button) return;
  const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  button.textContent = next === 'dark' ? '🌙' : '☀️';
  button.setAttribute('aria-label', next === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
};

document.addEventListener('click', (event) => {
  const target = event.target as HTMLElement;
  if (target?.id === 'theme-toggle') {
    toggle();
  }
});

document.addEventListener('DOMContentLoaded', () => {
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!button) return;
  const theme = document.documentElement.getAttribute('data-theme') ?? 'dark';
  button.textContent = theme === 'dark' ? '🌙' : '☀️';
  button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
});
