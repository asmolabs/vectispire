# Extracted Angular HTML Templates

## Standalone HTML Files

### frontend/src/app/add-repo/add-repo.html
```html
<p>add-repo works!</p>

```

### frontend/src/app/app.html
```html
<!-- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * -->
<!-- * * * * * * * * * * * The content below * * * * * * * * * * * -->
<!-- * * * * * * * * * * is only a placeholder * * * * * * * * * * -->
<!-- * * * * * * * * * * and can be replaced.  * * * * * * * * * * -->
<!-- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * -->
<!-- * * * * * * * * * Delete the template below * * * * * * * * * -->
<!-- * * * * * * * to get started with your project! * * * * * * * -->
<!-- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * -->

<style>
  :host {
    --bright-blue: oklch(51.01% 0.274 263.83);
    --electric-violet: oklch(53.18% 0.28 296.97);
    --french-violet: oklch(47.66% 0.246 305.88);
    --vivid-pink: oklch(69.02% 0.277 332.77);
    --hot-red: oklch(61.42% 0.238 15.34);
    --orange-red: oklch(63.32% 0.24 31.68);

    --gray-900: oklch(19.37% 0.006 300.98);
    --gray-700: oklch(36.98% 0.014 302.71);
    --gray-400: oklch(70.9% 0.015 304.04);

    --red-to-pink-to-purple-vertical-gradient: linear-gradient(
      180deg,
      var(--orange-red) 0%,
      var(--vivid-pink) 50%,
      var(--electric-violet) 100%
    );

    --red-to-pink-to-purple-horizontal-gradient: linear-gradient(
      90deg,
      var(--orange-red) 0%,
      var(--vivid-pink) 50%,
      var(--electric-violet) 100%
    );

    --pill-accent: var(--bright-blue);

    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
      Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji",
      "Segoe UI Symbol";
    box-sizing: border-box;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    display: block;
    height: 100dvh;
  }

  h1 {
    font-size: 3.125rem;
    color: var(--gray-900);
    font-weight: 500;
    line-height: 100%;
    letter-spacing: -0.125rem;
    margin: 0;
    font-family: "Inter Tight", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
      Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji",
      "Segoe UI Symbol";
  }

  p {
    margin: 0;
    color: var(--gray-700);
  }

  main {
    width: 100%;
    min-height: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 1rem;
    box-sizing: inherit;
    position: relative;
  }

  .angular-logo {
    max-width: 9.2rem;
  }

  .content {
    display: flex;
    justify-content: space-around;
    width: 100%;
    max-width: 700px;
    margin-bottom: 3rem;
  }

  .content h1 {
    margin-top: 1.75rem;
  }

  .content p {
    margin-top: 1.5rem;
  }

  .divider {
    width: 1px;
    background: var(--red-to-pink-to-purple-vertical-gradient);
    margin-inline: 0.5rem;
  }

  .pill-group {
    display: flex;
    flex-direction: column;
    align-items: start;
    flex-wrap: wrap;
    gap: 1.25rem;
  }

  .pill {
    display: flex;
    align-items: center;
    --pill-accent: var(--bright-blue);
    background: color-mix(in srgb, var(--pill-accent) 5%, transparent);
    color: var(--pill-accent);
    padding-inline: 0.75rem;
    padding-block: 0.375rem;
    border-radius: 2.75rem;
    border: 0;
    transition: background 0.3s ease;
    font-family: var(--inter-font);
    font-size: 0.875rem;
    font-style: normal;
    font-weight: 500;
    line-height: 1.4rem;
    letter-spacing: -0.00875rem;
    text-decoration: none;
    white-space: nowrap;
  }

  .pill:hover {
    background: color-mix(in srgb, var(--pill-accent) 15%, transparent);
  }

  .pill-group .pill:nth-child(6n + 1) {
    --pill-accent: var(--bright-blue);
  }
  .pill-group .pill:nth-child(6n + 2) {
    --pill-accent: var(--electric-violet);
  }
  .pill-group .pill:nth-child(6n + 3) {
    --pill-accent: var(--french-violet);
  }

  .pill-group .pill:nth-child(6n + 4),
  .pill-group .pill:nth-child(6n + 5),
  .pill-group .pill:nth-child(6n + 6) {
    --pill-accent: var(--hot-red);
  }

  .pill-group svg {
    margin-inline-start: 0.25rem;
  }

  .social-links {
    display: flex;
    align-items: center;
    gap: 0.73rem;
    margin-top: 1.5rem;
  }

  .social-links path {
    transition: fill 0.3s ease;
    fill: var(--gray-400);
  }

  .social-links a:hover svg path {
    fill: var(--gray-900);
  }

  @media screen and (max-width: 650px) {
    .content {
      flex-direction: column;
      width: max-content;
    }

    .divider {
      height: 1px;
      width: 100%;
      background: var(--red-to-pink-to-purple-horizontal-gradient);
      margin-block: 1.5rem;
    }
  }
</style>

<main class="main">
  <div class="content">
    <div class="left-side">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 982 239"
        fill="none"
        class="angular-logo"
      >
        <g clip-path="url(#a)">
          <path
            fill="url(#b)"
            d="M388.676 191.625h30.849L363.31 31.828h-35.758l-56.215 159.797h30.848l13.174-39.356h60.061l13.256 39.356Zm-65.461-62.675 21.602-64.311h1.227l21.602 64.311h-44.431Zm126.831-7.527v70.202h-28.23V71.839h27.002v20.374h1.392c2.782-6.71 7.2-12.028 13.255-15.956 6.056-3.927 13.584-5.89 22.503-5.89 8.264 0 15.465 1.8 21.684 5.318 6.137 3.518 10.964 8.673 14.319 15.382 3.437 6.71 5.074 14.81 4.992 24.383v76.175h-28.23v-71.92c0-8.019-2.046-14.237-6.219-18.819-4.173-4.5-9.819-6.791-17.102-6.791-4.91 0-9.328 1.063-13.174 3.272-3.846 2.128-6.792 5.237-9.001 9.328-2.046 4.009-3.191 8.918-3.191 14.728ZM589.233 239c-10.147 0-18.82-1.391-26.103-4.091-7.282-2.7-13.092-6.382-17.511-10.964-4.418-4.582-7.528-9.655-9.164-15.219l25.448-6.136c1.145 2.372 2.782 4.663 4.991 6.954 2.209 2.291 5.155 4.255 8.837 5.81 3.683 1.554 8.428 2.291 14.074 2.291 8.019 0 14.647-1.964 19.884-5.81 5.237-3.845 7.856-10.227 7.856-19.064v-22.665h-1.391c-1.473 2.946-3.601 5.892-6.383 9.001-2.782 3.109-6.464 5.645-10.965 7.691-4.582 2.046-10.228 3.109-17.101 3.109-9.165 0-17.511-2.209-25.039-6.545-7.446-4.337-13.42-10.883-17.757-19.474-4.418-8.673-6.628-19.473-6.628-32.565 0-13.091 2.21-24.301 6.628-33.383 4.419-9.082 10.311-15.955 17.839-20.7 7.528-4.746 15.874-7.037 25.039-7.037 7.037 0 12.846 1.145 17.347 3.518 4.582 2.373 8.182 5.236 10.883 8.51 2.7 3.272 4.746 6.382 6.137 9.327h1.554v-19.8h27.821v121.749c0 10.228-2.454 18.737-7.364 25.447-4.91 6.709-11.538 11.7-20.048 15.055-8.509 3.355-18.165 4.991-28.884 4.991Zm.245-71.266c5.974 0 11.047-1.473 15.302-4.337 4.173-2.945 7.446-7.118 9.573-12.519 2.21-5.482 3.274-12.027 3.274-19.637 0-7.609-1.064-14.155-3.274-19.8-2.127-5.646-5.318-10.064-9.491-13.255-4.174-3.11-9.329-4.746-15.384-4.746s-11.537 1.636-15.792 4.91c-4.173 3.272-7.365 7.772-9.492 13.418-2.128 5.727-3.191 12.191-3.191 19.392 0 7.2 1.063 13.745 3.273 19.228 2.127 5.482 5.318 9.736 9.573 12.764 4.174 3.027 9.41 4.582 15.629 4.582Zm141.56-26.51V71.839h28.23v119.786h-27.412v-21.273h-1.227c-2.7 6.709-7.119 12.191-13.338 16.446-6.137 4.255-13.747 6.382-22.748 6.382-7.855 0-14.81-1.718-20.783-5.237-5.974-3.518-10.72-8.591-14.075-15.382-3.355-6.709-5.073-14.891-5.073-24.464V71.839h28.312v71.921c0 7.609 2.046 13.664 6.219 18.083 4.173 4.5 9.655 6.709 16.365 6.709 4.173 0 8.183-.982 12.111-3.028 3.927-2.045 7.118-5.072 9.655-9.082 2.537-4.091 3.764-9.164 3.764-15.218Zm65.707-109.395v159.796h-28.23V31.828h28.23Zm44.841 162.169c-7.61 0-14.402-1.391-20.457-4.091-6.055-2.7-10.883-6.791-14.32-12.109-3.518-5.319-5.237-11.946-5.237-19.801 0-6.791 1.228-12.355 3.765-16.773 2.536-4.419 5.891-7.937 10.228-10.637 4.337-2.618 9.164-4.664 14.647-6.055 5.4-1.391 11.046-2.373 16.856-3.027 7.037-.737 12.683-1.391 17.102-1.964 4.337-.573 7.528-1.555 9.574-2.782 1.963-1.309 3.027-3.273 3.027-5.973v-.491c0-5.891-1.718-10.391-5.237-13.664-3.518-3.191-8.51-4.828-15.056-4.828-6.955 0-12.356 1.473-16.447 4.5-4.009 3.028-6.71 6.546-8.183 10.719l-26.348-3.764c2.046-7.282 5.483-13.336 10.31-18.328 4.746-4.909 10.638-8.59 17.511-11.045 6.955-2.455 14.565-3.682 22.912-3.682 5.809 0 11.537.654 17.265 2.045s10.965 3.6 15.711 6.71c4.746 3.109 8.51 7.282 11.455 12.6 2.864 5.318 4.337 11.946 4.337 19.883v80.184h-27.166v-16.446h-.9c-1.719 3.355-4.092 6.464-7.201 9.328-3.109 2.864-6.955 5.237-11.619 6.955-4.828 1.718-10.229 2.536-16.529 2.536Zm7.364-20.701c5.646 0 10.556-1.145 14.729-3.354 4.173-2.291 7.364-5.237 9.655-9.001 2.292-3.763 3.355-7.854 3.355-12.273v-14.155c-.9.737-2.373 1.391-4.5 2.046-2.128.654-4.419 1.145-7.037 1.636-2.619.491-5.155.9-7.692 1.227-2.537.328-4.746.655-6.628.901-4.173.572-8.019 1.472-11.292 2.781-3.355 1.31-5.973 3.11-7.855 5.401-1.964 2.291-2.864 5.318-2.864 8.918 0 5.237 1.882 9.164 5.728 11.782 3.682 2.782 8.51 4.091 14.401 4.091Zm64.643 18.328V71.839h27.412v19.965h1.227c2.21-6.955 5.974-12.274 11.292-16.038 5.319-3.763 11.456-5.645 18.329-5.645 1.555 0 3.355.082 5.237.163 1.964.164 3.601.328 4.91.573v25.938c-1.227-.41-3.109-.819-5.646-1.146a58.814 58.814 0 0 0-7.446-.49c-5.155 0-9.738 1.145-13.829 3.354-4.091 2.209-7.282 5.236-9.655 9.164-2.373 3.927-3.519 8.427-3.519 13.5v70.448h-28.312ZM222.077 39.192l-8.019 125.923L137.387 0l84.69 39.192Zm-53.105 162.825-57.933 33.056-57.934-33.056 11.783-28.556h92.301l11.783 28.556ZM111.039 62.675l30.357 73.803H80.681l30.358-73.803ZM7.937 165.115 0 39.192 84.69 0 7.937 165.115Z"
          />
          <path
            fill="url(#c)"
            d="M388.676 191.625h30.849L363.31 31.828h-35.758l-56.215 159.797h30.848l13.174-39.356h60.061l13.256 39.356Zm-65.461-62.675 21.602-64.311h1.227l21.602 64.311h-44.431Zm126.831-7.527v70.202h-28.23V71.839h27.002v20.374h1.392c2.782-6.71 7.2-12.028 13.255-15.956 6.056-3.927 13.584-5.89 22.503-5.89 8.264 0 15.465 1.8 21.684 5.318 6.137 3.518 10.964 8.673 14.319 15.382 3.437 6.71 5.074 14.81 4.992 24.383v76.175h-28.23v-71.92c0-8.019-2.046-14.237-6.219-18.819-4.173-4.5-9.819-6.791-17.102-6.791-4.91 0-9.328 1.063-13.174 3.272-3.846 2.128-6.792 5.237-9.001 9.328-2.046 4.009-3.191 8.918-3.191 14.728ZM589.233 239c-10.147 0-18.82-1.391-26.103-4.091-7.282-2.7-13.092-6.382-17.511-10.964-4.418-4.582-7.528-9.655-9.164-15.219l25.448-6.136c1.145 2.372 2.782 4.663 4.991 6.954 2.209 2.291 5.155 4.255 8.837 5.81 3.683 1.554 8.428 2.291 14.074 2.291 8.019 0 14.647-1.964 19.884-5.81 5.237-3.845 7.856-10.227 7.856-19.064v-22.665h-1.391c-1.473 2.946-3.601 5.892-6.383 9.001-2.782 3.109-6.464 5.645-10.965 7.691-4.582 2.046-10.228 3.109-17.101 3.109-9.165 0-17.511-2.209-25.039-6.545-7.446-4.337-13.42-10.883-17.757-19.474-4.418-8.673-6.628-19.473-6.628-32.565 0-13.091 2.21-24.301 6.628-33.383 4.419-9.082 10.311-15.955 17.839-20.7 7.528-4.746 15.874-7.037 25.039-7.037 7.037 0 12.846 1.145 17.347 3.518 4.582 2.373 8.182 5.236 10.883 8.51 2.7 3.272 4.746 6.382 6.137 9.327h1.554v-19.8h27.821v121.749c0 10.228-2.454 18.737-7.364 25.447-4.91 6.709-11.538 11.7-20.048 15.055-8.509 3.355-18.165 4.991-28.884 4.991Zm.245-71.266c5.974 0 11.047-1.473 15.302-4.337 4.173-2.945 7.446-7.118 9.573-12.519 2.21-5.482 3.274-12.027 3.274-19.637 0-7.609-1.064-14.155-3.274-19.8-2.127-5.646-5.318-10.064-9.491-13.255-4.174-3.11-9.329-4.746-15.384-4.746s-11.537 1.636-15.792 4.91c-4.173 3.272-7.365 7.772-9.492 13.418-2.128 5.727-3.191 12.191-3.191 19.392 0 7.2 1.063 13.745 3.273 19.228 2.127 5.482 5.318 9.736 9.573 12.764 4.174 3.027 9.41 4.582 15.629 4.582Zm141.56-26.51V71.839h28.23v119.786h-27.412v-21.273h-1.227c-2.7 6.709-7.119 12.191-13.338 16.446-6.137 4.255-13.747 6.382-22.748 6.382-7.855 0-14.81-1.718-20.783-5.237-5.974-3.518-10.72-8.591-14.075-15.382-3.355-6.709-5.073-14.891-5.073-24.464V71.839h28.312v71.921c0 7.609 2.046 13.664 6.219 18.083 4.173 4.5 9.655 6.709 16.365 6.709 4.173 0 8.183-.982 12.111-3.028 3.927-2.045 7.118-5.072 9.655-9.082 2.537-4.091 3.764-9.164 3.764-15.218Zm65.707-109.395v159.796h-28.23V31.828h28.23Zm44.841 162.169c-7.61 0-14.402-1.391-20.457-4.091-6.055-2.7-10.883-6.791-14.32-12.109-3.518-5.319-5.237-11.946-5.237-19.801 0-6.791 1.228-12.355 3.765-16.773 2.536-4.419 5.891-7.937 10.228-10.637 4.337-2.618 9.164-4.664 14.647-6.055 5.4-1.391 11.046-2.373 16.856-3.027 7.037-.737 12.683-1.391 17.102-1.964 4.337-.573 7.528-1.555 9.574-2.782 1.963-1.309 3.027-3.273 3.027-5.973v-.491c0-5.891-1.718-10.391-5.237-13.664-3.518-3.191-8.51-4.828-15.056-4.828-6.955 0-12.356 1.473-16.447 4.5-4.009 3.028-6.71 6.546-8.183 10.719l-26.348-3.764c2.046-7.282 5.483-13.336 10.31-18.328 4.746-4.909 10.638-8.59 17.511-11.045 6.955-2.455 14.565-3.682 22.912-3.682 5.809 0 11.537.654 17.265 2.045s10.965 3.6 15.711 6.71c4.746 3.109 8.51 7.282 11.455 12.6 2.864 5.318 4.337 11.946 4.337 19.883v80.184h-27.166v-16.446h-.9c-1.719 3.355-4.092 6.464-7.201 9.328-3.109 2.864-6.955 5.237-11.619 6.955-4.828 1.718-10.229 2.536-16.529 2.536Zm7.364-20.701c5.646 0 10.556-1.145 14.729-3.354 4.173-2.291 7.364-5.237 9.655-9.001 2.292-3.763 3.355-7.854 3.355-12.273v-14.155c-.9.737-2.373 1.391-4.5 2.046-2.128.654-4.419 1.145-7.037 1.636-2.619.491-5.155.9-7.692 1.227-2.537.328-4.746.655-6.628.901-4.173.572-8.019 1.472-11.292 2.781-3.355 1.31-5.973 3.11-7.855 5.401-1.964 2.291-2.864 5.318-2.864 8.918 0 5.237 1.882 9.164 5.728 11.782 3.682 2.782 8.51 4.091 14.401 4.091Zm64.643 18.328V71.839h27.412v19.965h1.227c2.21-6.955 5.974-12.274 11.292-16.038 5.319-3.763 11.456-5.645 18.329-5.645 1.555 0 3.355.082 5.237.163 1.964.164 3.601.328 4.91.573v25.938c-1.227-.41-3.109-.819-5.646-1.146a58.814 58.814 0 0 0-7.446-.49c-5.155 0-9.738 1.145-13.829 3.354-4.091 2.209-7.282 5.236-9.655 9.164-2.373 3.927-3.519 8.427-3.519 13.5v70.448h-28.312ZM222.077 39.192l-8.019 125.923L137.387 0l84.69 39.192Zm-53.105 162.825-57.933 33.056-57.934-33.056 11.783-28.556h92.301l11.783 28.556ZM111.039 62.675l30.357 73.803H80.681l30.358-73.803ZM7.937 165.115 0 39.192 84.69 0 7.937 165.115Z"
          />
        </g>
        <defs>
          <radialGradient
            id="c"
            cx="0"
            cy="0"
            r="1"
            gradientTransform="rotate(118.122 171.182 60.81) scale(205.794)"
            gradientUnits="userSpaceOnUse"
          >
            <stop stop-color="#FF41F8" />
            <stop offset=".707" stop-color="#FF41F8" stop-opacity=".5" />
            <stop offset="1" stop-color="#FF41F8" stop-opacity="0" />
          </radialGradient>
          <linearGradient
            id="b"
            x1="0"
            x2="982"
            y1="192"
            y2="192"
            gradientUnits="userSpaceOnUse"
          >
            <stop stop-color="#F0060B" />
            <stop offset="0" stop-color="#F0070C" />
            <stop offset=".526" stop-color="#CC26D5" />
            <stop offset="1" stop-color="#7702FF" />
          </linearGradient>
          <clipPath id="a"><path fill="#fff" d="M0 0h982v239H0z" /></clipPath>
        </defs>
      </svg>
      <h1>Hello, {{ title() }}</h1>
      <p>Congratulations! Your app is running. 🎉</p>
    </div>
    <div class="divider" role="separator" aria-label="Divider"></div>
    <div class="right-side">
      <div class="pill-group">
        @for (item of [
          { title: 'Explore the Docs', link: 'https://angular.dev' },
          { title: 'Learn with Tutorials', link: 'https://angular.dev/tutorials' },
          { title: 'Prompt and best practices for AI', link: 'https://angular.dev/ai/develop-with-ai'},
          { title: 'CLI Docs', link: 'https://angular.dev/tools/cli' },
          { title: 'Angular Language Service', link: 'https://angular.dev/tools/language-service' },
          { title: 'Angular DevTools', link: 'https://angular.dev/tools/devtools' },
        ]; track item.title) {
          <a
            class="pill"
            [href]="item.link"
            target="_blank"
            rel="noopener"
          >
            <span>{{ item.title }}</span>
            <svg
              xmlns="http://www.w3.org/2000/svg"
              height="14"
              viewBox="0 -960 960 960"
              width="14"
              fill="currentColor"
            >
              <path
                d="M200-120q-33 0-56.5-23.5T120-200v-560q0-33 23.5-56.5T200-840h280v80H200v560h560v-280h80v280q0 33-23.5 56.5T760-120H200Zm188-212-56-56 372-372H560v-80h280v280h-80v-144L388-332Z"
              />
            </svg>
          </a>
        }
      </div>
      <div class="social-links">
        <a
          href="https://github.com/angular/angular"
          aria-label="Github"
          target="_blank"
          rel="noopener"
        >
          <svg
            width="25"
            height="24"
            viewBox="0 0 25 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            alt="Github"
          >
            <path
              d="M12.3047 0C5.50634 0 0 5.50942 0 12.3047C0 17.7423 3.52529 22.3535 8.41332 23.9787C9.02856 24.0946 9.25414 23.7142 9.25414 23.3871C9.25414 23.0949 9.24389 22.3207 9.23876 21.2953C5.81601 22.0377 5.09414 19.6444 5.09414 19.6444C4.53427 18.2243 3.72524 17.8449 3.72524 17.8449C2.61064 17.082 3.81137 17.0973 3.81137 17.0973C5.04697 17.1835 5.69604 18.3647 5.69604 18.3647C6.79321 20.2463 8.57636 19.7029 9.27978 19.3881C9.39052 18.5924 9.70736 18.0499 10.0591 17.7423C7.32641 17.4347 4.45429 16.3765 4.45429 11.6618C4.45429 10.3185 4.9311 9.22133 5.72065 8.36C5.58222 8.04931 5.16694 6.79833 5.82831 5.10337C5.82831 5.10337 6.85883 4.77319 9.2121 6.36459C10.1965 6.09082 11.2424 5.95546 12.2883 5.94931C13.3342 5.95546 14.3801 6.09082 15.3644 6.36459C17.7023 4.77319 18.7328 5.10337 18.7328 5.10337C19.3942 6.79833 18.9789 8.04931 18.8559 8.36C19.6403 9.22133 20.1171 10.3185 20.1171 11.6618C20.1171 16.3888 17.2409 17.4296 14.5031 17.7321C14.9338 18.1012 15.3337 18.8559 15.3337 20.0084C15.3337 21.6552 15.3183 22.978 15.3183 23.3779C15.3183 23.7009 15.5336 24.0854 16.1642 23.9623C21.0871 22.3484 24.6094 17.7341 24.6094 12.3047C24.6094 5.50942 19.0999 0 12.3047 0Z"
            />
          </svg>
        </a>
        <a
          href="https://x.com/angular"
          aria-label="X"
          target="_blank"
          rel="noopener"
        >
          <svg
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            alt="X"
          >
            <path
              d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"
            />
          </svg>
        </a>
        <a
          href="https://www.youtube.com/channel/UCbn1OgGei-DV7aSRo_HaAiw"
          aria-label="Youtube"
          target="_blank"
          rel="noopener"
        >
          <svg
            width="29"
            height="20"
            viewBox="0 0 29 20"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            alt="Youtube"
          >
            <path
              fill-rule="evenodd"
              clip-rule="evenodd"
              d="M27.4896 1.52422C27.9301 1.96749 28.2463 2.51866 28.4068 3.12258C29.0004 5.35161 29.0004 10 29.0004 10C29.0004 10 29.0004 14.6484 28.4068 16.8774C28.2463 17.4813 27.9301 18.0325 27.4896 18.4758C27.0492 18.9191 26.5 19.2389 25.8972 19.4032C23.6778 20 14.8068 20 14.8068 20C14.8068 20 5.93586 20 3.71651 19.4032C3.11363 19.2389 2.56449 18.9191 2.12405 18.4758C1.68361 18.0325 1.36732 17.4813 1.20683 16.8774C0.613281 14.6484 0.613281 10 0.613281 10C0.613281 10 0.613281 5.35161 1.20683 3.12258C1.36732 2.51866 1.68361 1.96749 2.12405 1.52422C2.56449 1.08095 3.11363 0.76113 3.71651 0.596774C5.93586 0 14.8068 0 14.8068 0C14.8068 0 23.6778 0 25.8972 0.596774C26.5 0.76113 27.0492 1.08095 27.4896 1.52422ZM19.3229 10L11.9036 5.77905V14.221L19.3229 10Z"
            />
          </svg>
        </a>
      </div>
    </div>
  </div>
</main>

<!-- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * -->
<!-- * * * * * * * * * * * The content above * * * * * * * * * * * * -->
<!-- * * * * * * * * * * is only a placeholder * * * * * * * * * * * -->
<!-- * * * * * * * * * * and can be replaced.  * * * * * * * * * * * -->
<!-- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * -->
<!-- * * * * * * * * * * End of Placeholder  * * * * * * * * * * * * -->
<!-- * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * -->


<router-outlet />

```

### frontend/src/app/repo-list/repo-list.html
```html
<p>repo-list works!</p>

```

## Inline Templates in TypeScript Files

### frontend/src/app/add-repo/add-repo.ts
```html
<div class="card shadow-1 border-round p-4 surface-card mb-4">
      <h2 class="text-2xl font-bold mb-2">Git Security Scanner</h2>
      <p class="text-secondary mb-4">Analyze Git repositories with Syft (SBOM) and Grype (CVEs)</p>
      
      <div class="add-repo-form p-fluid mx-auto" style="max-width: 1000px;">
        <div class="grid align-items-end">
          <div class="col-12 md:col-3">
            <label for="repoName" class="block font-bold mb-2 text-sm text-secondary">Nom du dépôt (Optionnel)</label>
            <div class="p-inputgroup">
              <span class="p-inputgroup-addon"><i class="pi pi-tag"></i></span>
              <input pInputText id="repoName" type="text" [(ngModel)]="repoName" placeholder="Ex: Mon Projet" class="w-full" />
            </div>
          </div>
          <div class="col-12 md:col-6">
            <label for="repoUrl" class="block font-bold mb-2 text-sm text-secondary">URL du dépôt</label>
            <div class="p-inputgroup">
              <span class="p-inputgroup-addon"><i class="pi pi-link"></i></span>
              <input pInputText id="repoUrl" type="text" [(ngModel)]="repoUrl" placeholder="https://github.com/user/repo.git" class="w-full" />
            </div>
          </div>
          <div class="col-12 md:col-3">
            <label for="branch" class="block font-bold mb-2 text-sm text-secondary">Branche</label>
            <input pInputText id="branch" type="text" [(ngModel)]="branch" placeholder="main" class="w-full" />
          </div>
          <div class="col-12 md:col-6 mt-3">
            <label for="subPath" class="block font-bold mb-2 text-sm text-secondary">Chemin d'analyse (Optionnel)</label>
            <div class="p-inputgroup">
              <span class="p-inputgroup-addon"><i class="pi pi-folder"></i></span>
              <input pInputText id="subPath" type="text" [(ngModel)]="subPath" placeholder="Ex: backend/src" class="w-full" />
            </div>
            <small class="text-secondary">Laissez vide pour scanner tout le dépôt.</small>
          </div>
          <div class="col-12 md:col-6 mt-3">
            <label for="sshKey" class="block font-bold mb-2 text-sm text-secondary">Clé SSH (Optionnel)</label>
            <p-select [options]="sshKeys" [(ngModel)]="selectedSshKeyId" optionLabel="name" optionValue="id" placeholder="Sélectionnez une clé SSH" [showClear]="true" class="w-full"></p-select>
            <div class="mt-1">
              <a routerLink="/ssh-keys" class="text-xs text-primary no-underline hover:underline"><i class="pi pi-cog mr-1"></i>Gérer les clés SSH</a>
            </div>
          </div>
          <div class="col-12 md:col-3 mt-3">
            <p-button label="Ajouter & Scanner" icon="pi pi-plus" [loading]="isLoading" [disabled]="!repoUrl" (onClick)="onSubmit()" styleClass="p-button-raised w-full"></p-button>
          </div>
          <div class="col-12">
              <small class="text-secondary ml-1">Supporte les URLs HTTPS et SSH. Par défaut 'main' si vide.</small>
          </div>
          <div class="col-12 mt-2" *ngIf="errorMessage">
            <p-message severity="error" [text]="errorMessage" class="w-full"></p-message>
          </div>
        </div>
      </div>
    </div>
```

### frontend/src/app/admin/admin-settings.component.ts
```html
<div class="grid">
      <div class="col-12">
        <p-card header="Paramètres d'Administration">
          <p class="text-600 mb-4">
            Configurez les méthodes de connexion, les notifications et les alertes de sécurité.
          </p>

          <div *ngIf="loading" class="flex align-items-center justify-content-center p-4">
            <i class="pi pi-spin pi-spinner" style="font-size: 2rem"></i>
          </div>

          <p-tabs *ngIf="!loading" value="0">
            <p-tablist>
                <p-tab value="0">
                    <i class="pi pi-shield mr-2"></i>
                    <span>Authentification</span>
                </p-tab>
                <p-tab value="1">
                    <i class="pi pi-envelope mr-2"></i>
                    <span>Serveur SMTP</span>
                </p-tab>
                <p-tab value="2">
                    <i class="pi pi-bell mr-2"></i>
                    <span>Alertes Email</span>
                </p-tab>
                <p-tab value="3">
                    <i class="pi pi-microsoft mr-2"></i>
                    <span>Teams</span>
                </p-tab>
            </p-tablist>
            
            <p-tabpanels>
                <!-- Onglet Authentification -->
                <p-tabpanel value="0">
                    <div class="flex flex-column gap-4 mt-3">
                        <div class="flex align-items-center justify-content-between border-bottom-1 border-300 pb-3">
                        <div>
                            <div class="text-xl font-bold mb-1">Connexion Locale</div>
                            <div class="text-sm text-500">Activée par défaut (Nom d'utilisateur et mot de passe)</div>
                        </div>
                        <p-toggleswitch [ngModel]="true" [disabled]="true"></p-toggleswitch>
                        </div>

                        <div class="flex align-items-center justify-content-between border-bottom-1 border-300 pb-3">
                        <div>
                            <div class="text-xl font-bold mb-1">Connexion GitHub</div>
                            <div class="text-sm text-500">Permettre aux utilisateurs de se connecter via leur compte GitHub</div>
                        </div>
                        <p-toggleswitch [(ngModel)]="authSettings.githubEnabled" (onChange)="onSettingChange()"></p-toggleswitch>
                        </div>

                        <div class="flex align-items-center justify-content-between pb-3">
                        <div>
                            <div class="text-xl font-bold mb-1">Connexion Keycloak</div>
                            <div class="text-sm text-500">Permettre aux utilisateurs de se connecter via Keycloak (SSO)</div>
                        </div>
                        <p-toggleswitch [(ngModel)]="authSettings.keycloakEnabled" (onChange)="onSettingChange()"></p-toggleswitch>
                        </div>
                    </div>
                </p-tabpanel>

                <!-- Onglet SMTP -->
                <p-tabpanel value="1">
                    <div class="flex flex-column gap-3 mt-3">
                        <div class="grid">
                            <div class="col-12 md:col-8">
                                <label for="smtpHost" class="block font-bold mb-2">Hôte SMTP</label>
                                <input pInputText id="smtpHost" [(ngModel)]="emailSettings.smtpHost" (ngModelChange)="onSettingChange()" class="w-full" placeholder="ex: smtp.mailtrap.io" />
                            </div>
                            <div class="col-12 md:col-4">
                                <label for="smtpPort" class="block font-bold mb-2">Port</label>
                                <input pInputText id="smtpPort" [(ngModel)]="emailSettings.smtpPort" (ngModelChange)="onSettingChange()" class="w-full" placeholder="ex: 587" />
                            </div>
                            <div class="col-12 md:col-6">
                                <label for="smtpUser" class="block font-bold mb-2">Utilisateur SMTP</label>
                                <input pInputText id="smtpUser" [(ngModel)]="emailSettings.smtpUser" (ngModelChange)="onSettingChange()" class="w-full" />
                            </div>
                            <div class="col-12 md:col-6">
                                <label for="smtpPass" class="block font-bold mb-2">Mot de passe SMTP</label>
                                <p-password id="smtpPass" [(ngModel)]="emailSettings.smtpPass" (ngModelChange)="onSettingChange()" [feedback]="false" [toggleMask]="true" styleClass="w-full" inputStyleClass="w-full"></p-password>
                            </div>
                            <div class="col-12">
                                <label for="smtpFrom" class="block font-bold mb-2">Adresse de l'expéditeur (From)</label>
                                <input pInputText id="smtpFrom" [(ngModel)]="emailSettings.smtpFrom" (ngModelChange)="onSettingChange()" class="w-full" placeholder="ex: noreply@zanshin.local" />
                            </div>
                        </div>
                        <div class="mt-4 p-3 border-1 border-300 border-round bg-gray-50">
                            <div class="font-bold mb-3">Tester la configuration Email</div>
                            <div class="flex gap-2">
                                <input pInputText [(ngModel)]="testEmailAddress" class="flex-grow-1" placeholder="Email de destination pour le test" />
                                <p-button label="Envoyer un test" icon="pi pi-send" severity="secondary" [loading]="testingEmail" (onClick)="testEmail()" [disabled]="!emailSettings.smtpHost"></p-button>
                            </div>
                        </div>
                    </div>
                </p-tabpanel>

                <!-- Onglet Alertes Email -->
                <p-tabpanel value="2">
                    <div class="flex flex-column gap-3 mt-3">
                        <div class="field">
                            <label for="alertEmails" class="block font-bold mb-2">Adresses E-mail d'alerte</label>
                            <input pInputText id="alertEmails" [(ngModel)]="alertSettings.alertEmails" (ngModelChange)="onSettingChange()" class="w-full" placeholder="Séparées par des virgules (ex: admin@zanshin.com, secu@zanshin.com)" />
                            <small class="text-500">Un e-mail sera envoyé à ces adresses lors de la détection de failles.</small>
                        </div>

                        <div class="field mt-3">
                            <label for="alertMinSeverity" class="block font-bold mb-2">Sévérité minimale pour alerter (Email & Teams)</label>
                            <p-select id="alertMinSeverity" [options]="severityOptions" [(ngModel)]="alertSettings.alertMinSeverity" (ngModelChange)="onSettingChange()" optionLabel="label" optionValue="value" styleClass="w-full md:w-20rem"></p-select>
                            <small class="block mt-1 text-500">Seuls les scans détectant des vulnérabilités de ce niveau ou supérieur déclencheront une notification.</small>
                        </div>
                    </div>
                </p-tabpanel>

                <!-- Onglet Teams -->
                <p-tabpanel value="3">
                    <div class="flex flex-column gap-3 mt-3">
                        <div class="flex align-items-center justify-content-between border-bottom-1 border-300 pb-3 mb-3">
                            <div>
                                <div class="text-xl font-bold mb-1">Notifications Teams</div>
                                <div class="text-sm text-500">Envoyer les alertes de sécurité vers un canal Microsoft Teams</div>
                            </div>
                            <p-toggleswitch [(ngModel)]="teamsSettings.enabled" (onChange)="onSettingChange()"></p-toggleswitch>
                        </div>

                        <div class="field" [class.opacity-50]="!teamsSettings.enabled">
                            <label for="teamsWebhook" class="block font-bold mb-2">URL du Webhook Teams</label>
                            <input pInputText id="teamsWebhook" [(ngModel)]="teamsSettings.webhookUrl" (ngModelChange)="onSettingChange()" class="w-full" placeholder="https://outlook.office.com/webhook/..." [disabled]="!teamsSettings.enabled" />
                            <small class="text-500">Utilisez un connecteur "Incoming Webhook" (ou un Workflow Teams) pour obtenir cette URL.</small>
                        </div>

                        <div class="mt-4 p-3 border-1 border-300 border-round bg-gray-50" *ngIf="teamsSettings.enabled">
                            <div class="font-bold mb-3">Tester la connexion Teams</div>
                            <div class="flex gap-2">
                                <p-button label="Envoyer un message de test" icon="pi pi-microsoft" severity="secondary" [loading]="testingTeams" (onClick)="testTeams()" [disabled]="!teamsSettings.webhookUrl"></p-button>
                            </div>
                        </div>
                    </div>
                </p-tabpanel>
            </p-tabpanels>
          </p-tabs>

          <div class="flex justify-content-end mt-4" *ngIf="!loading">
            <p-button label="Enregistrer les modifications" icon="pi pi-save" [loading]="saving" (onClick)="saveSettings()" [disabled]="!hasChanges"></p-button>
          </div>
        </p-card>
      </div>
    </div>
    <p-toast></p-toast>
```

### frontend/src/app/api-keys/api-keys.ts
```html
<div class="card shadow-1 border-round p-4 surface-card">
      <p-toast position="bottom-right"></p-toast>
      
      <div class="flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center mb-4 gap-3">
        <div>
          <h2 class="text-2xl font-bold m-0 text-900">Clés d'API</h2>
          <p class="text-secondary mt-1">Gérez vos clés d'accès pour les déclenchements de scan externes</p>
        </div>
        <div class="flex align-items-center gap-3 w-full sm:w-auto">
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto p-inputtext-sm" />
          </span>
          <p-button label="Générer" icon="pi pi-plus" (onClick)="showCreateDialog()" size="small"></p-button>
        </div>
      </div>

      <p-table #dt [value]="apiKeys" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
               [globalFilterFields]="['name']"
               responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
        <ng-template pTemplate="header">
          <tr>
            <th pSortableColumn="name">Nom <p-sortIcon field="name"></p-sortIcon></th>
            <th pSortableColumn="lastUsedAt" style="width: 25%">Dernière utilisation <p-sortIcon field="lastUsedAt"></p-sortIcon></th>
            <th pSortableColumn="createdAt" style="width: 25%">Date de création <p-sortIcon field="createdAt"></p-sortIcon></th>
            <th class="text-center" style="width: 100px">Actions</th>
          </tr>
        </ng-template>
        <ng-template pTemplate="body" let-key>
          <tr class="hover:surface-50 transition-colors">
            <td>
              <div class="flex align-items-center gap-2">
                <i class="pi pi-shield text-primary"></i>
                <span class="font-bold text-900">{{ key.name }}</span>
              </div>
            </td>
            <td>
              <p-tag [value]="(key.lastUsedAt | date:'dd/MM/yyyy HH:mm') || 'Jamais utilisée'" 
                     [severity]="key.lastUsedAt ? 'success' : 'secondary'"
                     [rounded]="true"
                     styleClass="text-xs">
              </p-tag>
            </td>
            <td class="text-sm text-secondary">{{ key.createdAt | date:'dd/MM/yyyy HH:mm' }}</td>
            <td class="text-center">
              <p-button icon="pi pi-trash" size="small" severity="danger" [text]="true" 
                       (onClick)="deleteKey(key.id)" pTooltip="Supprimer la clé"></p-button>
            </td>
          </tr>
        </ng-template>
        <ng-template pTemplate="emptymessage">
          <tr>
            <td colspan="4" class="text-center p-5 text-secondary">
              <i class="pi pi-key text-4xl block mb-3"></i>
              Aucune clé d'API trouvée.
            </td>
          </tr>
        </ng-template>
      </p-table>

      <!-- Create Key Dialog -->
      <p-dialog header="Générer une nouvelle clé d'API" [(visible)]="createDialogVisible" 
                [modal]="true" [style]="{ width: '450px' }" [draggable]="false" [resizable]="false"
                styleClass="border-round-xl">
        <div class="p-fluid pt-2">
          <p class="text-secondary mb-4">Donnez un nom descriptif à votre clé (ex: Jenkins CI, GitHub Action).</p>
          <div class="field mb-4">
            <label for="keyName" class="font-bold text-900 block mb-2">Nom de la clé</label>
            <input pInputText id="keyName" [(ngModel)]="newKeyName" placeholder="Mon projet CI" />
          </div>
          <div class="flex justify-content-end gap-2">
            <p-button label="Annuler" severity="secondary" [text]="true" (onClick)="createDialogVisible = false"></p-button>
            <p-button label="Générer" icon="pi pi-check" (onClick)="createKey()" [disabled]="!newKeyName"></p-button>
          </div>
        </div>
      </p-dialog>

      <!-- Raw Key Display Dialog (Shown once) -->
      <p-dialog header="Clé d'API générée" [(visible)]="rawKeyDialogVisible" 
                [modal]="true" [style]="{ width: '450px' }" [closable]="false"
                styleClass="border-round-xl">
        <div class="pt-2">
          <div class="p-3 bg-orange-50 text-orange-700 border-round mb-4 text-sm font-bold flex align-items-center gap-2">
            <i class="pi pi-exclamation-triangle"></i>
            Attention : Cette clé ne sera affichée qu'une seule fois.
          </div>
          
          <div class="surface-100 p-3 border-round border-1 border-300 flex align-items-center justify-content-between mb-4">
            <code class="text-lg font-bold text-primary select-all overflow-hidden text-overflow-ellipsis">
              {{ generatedRawKey }}
            </code>
            <p-button icon="pi pi-copy" [text]="true" (onClick)="copyToClipboard(generatedRawKey)" pTooltip="Copier"></p-button>
          </div>

          <div class="flex justify-content-end">
            <p-button label="J'ai copié la clé" icon="pi pi-check" (onClick)="rawKeyDialogVisible = false" severity="success"></p-button>
          </div>
        </div>
      </p-dialog>
    </div>
```

### frontend/src/app/app.ts
```html
<router-outlet></router-outlet>
```

### frontend/src/app/auth/login.component.ts
```html
<div class="login-container flex align-items-center justify-content-center min-vh-100 p-4">
      <p-card class="login-card w-full md:w-30rem">
        <div class="text-center mb-5">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mb-3 text-primary">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
            <h1 class="text-3xl font-bold m-0 mb-2">Zanshin</h1>
            <p class="text-600 m-0">{{ isRegistering ? 'Créer un compte' : 'Veuillez vous connecter pour continuer' }}</p>
        </div>

        <div class="flex flex-column gap-3">
            <!-- Local Auth Form -->
            <form [formGroup]="authForm" (ngSubmit)="onSubmit()" class="flex flex-column gap-3">
                <div class="field flex flex-column gap-2">
                    <label for="username" class="font-bold">Nom d'utilisateur</label>
                    <input pInputText id="username" formControlName="username" placeholder="Entrez votre nom d'utilisateur" class="w-full" />
                </div>

                <div class="field flex flex-column gap-2" *ngIf="isRegistering">
                    <label for="email" class="font-bold">Email</label>
                    <input pInputText id="email" formControlName="email" type="email" placeholder="Entrez votre email" class="w-full" />
                </div>

                <div class="field flex flex-column gap-2" *ngIf="isRegistering">
                    <label for="displayName" class="font-bold">Nom d'affichage</label>
                    <input pInputText id="displayName" formControlName="displayName" placeholder="Entrez votre nom complet" class="w-full" />
                </div>

                <div class="field flex flex-column gap-2">
                    <label for="password" class="font-bold">Mot de passe</label>
                    <p-password 
                        id="password" 
                        formControlName="password" 
                        [toggleMask]="true" 
                        [feedback]="isRegistering"
                        placeholder="Entrez votre mot de passe"
                        styleClass="w-full"
                        inputStyleClass="w-full">
                    </p-password>
                </div>

                <p-button 
                    [label]="isRegistering ? 'S\\'enregistrer' : 'Se connecter'" 
                    type="submit"
                    styleClass="w-full p-button-primary mt-2" 
                    [loading]="loading"
                    [disabled]="authForm.invalid">
                </p-button>

                <div class="text-center" *ngIf="registrationAllowed || isRegistering">
                    <a href="javascript:void(0)" (click)="toggleMode()" class="text-primary font-medium">
                        {{ isRegistering ? 'Déjà un compte ? Se connecter' : 'Pas de compte ? S\\'enregistrer' }}
                    </a>
                </div>

            </form>



            <ng-container *ngIf="settings.githubEnabled || settings.keycloakEnabled">
                <p-divider align="center">
                    <span class="text-400 font-medium">OU</span>
                </p-divider>

                <div class="flex flex-column gap-3">
                    <p-button *ngIf="settings.githubEnabled"
                        label="Se connecter avec GitHub" 
                        icon="pi pi-github" 
                        styleClass="w-full p-button-secondary" 
                        (onClick)="loginWithGitHub()"
                        [disabled]="loading">
                    </p-button>
                    
                    <p-button *ngIf="settings.keycloakEnabled"
                        label="Se connecter avec Keycloak" 
                        icon="pi pi-lock" 
                        styleClass="w-full" 
                        (onClick)="loginWithKeycloak()"
                        [loading]="loading">
                    </p-button>
                </div>
            </ng-container>
            
            <div class="text-center mt-3" *ngIf="error">
                <p-message severity="error" [text]="error"></p-message>
            </div>
        </div>
      </p-card>
    </div>
```

### frontend/src/app/containers/add-container/add-container.ts
```html
<div class="flex justify-content-center align-items-center h-full pt-6">
      <p-card header="Ajouter une image Docker" subheader="Configurez une image Docker à scanner avec Syft et Grype" class="w-full max-w-30rem shadow-2">
        
        <div *ngIf="error" class="mb-4">
          <p-message severity="error" [text]="error" styleClass="w-full"></p-message>
        </div>

        <div class="flex flex-column gap-4">
          <div class="flex flex-column gap-2">
            <label for="registry" class="font-semibold text-900">Registre (Optionnel)</label>
            <input pInputText id="registry" [(ngModel)]="registry" placeholder="ex: docker.io (laisser vide pour défaut)" />
            <small class="text-500">L'URL du registre si ce n'est pas Docker Hub.</small>
          </div>

          <div class="flex flex-column gap-2">
            <label for="imageName" class="font-semibold text-900">Nom de l'image <span class="text-red-500">*</span></label>
            <input pInputText id="imageName" [(ngModel)]="imageName" placeholder="ex: nginx, alpine, mon-app" />
          </div>

          <div class="flex flex-column gap-2">
            <label for="tag" class="font-semibold text-900">Tag <span class="text-red-500">*</span></label>
            <input pInputText id="tag" [(ngModel)]="tag" placeholder="ex: latest, 1.2.3" />
          </div>
        </div>

        <ng-template pTemplate="footer">
          <div class="flex justify-content-end gap-3 mt-4">
            <p-button label="Annuler" icon="pi pi-times" [outlined]="true" severity="secondary" (click)="cancel()"></p-button>
            <p-button label="Ajouter" icon="pi pi-check" (click)="addContainer()" [loading]="loading" [disabled]="!imageName || !tag"></p-button>
          </div>
        </ng-template>
      </p-card>
    </div>
```

### frontend/src/app/containers/containers.ts
```html
<div class="depots-page">
      <p-toast></p-toast>
      <p-confirmDialog header="Confirmation" icon="pi pi-exclamation-triangle"></p-confirmDialog>

      <!-- Header Section -->
      <div class="flex justify-content-between align-items-center mb-5">
        <div class="flex align-items-center gap-3">
          <p-button *ngIf="view === 'details'" icon="pi pi-arrow-left" [rounded]="true" [text]="true" (click)="goBack()" pTooltip="Retour à la liste"></p-button>
          <div>
            <h2 class="text-3xl font-bold m-0 text-900">{{ view === 'list' ? 'Conteneurs Docker' : selectedContainer?.imageName }}</h2>
            <p class="text-secondary m-0 mt-1">{{ view === 'list' ? 'Gérez et explorez vos images Docker' : 'Configuration et historique des scans' }}</p>
          </div>
        </div>
        <div class="flex gap-2" *ngIf="view === 'list'">
            <p-button icon="pi pi-refresh" [rounded]="true" [text]="true" (click)="fetchContainers()" [loading]="loading" pTooltip="Actualiser"></p-button>
            <p-button label="Ajouter un conteneur" icon="pi pi-plus" [rounded]="true" routerLink="/add-container"></p-button>
        </div>
        <div class="flex gap-2" *ngIf="view === 'details'">
            <p-button label="Configurer" icon="pi pi-cog" [outlined]="true" [rounded]="true" (click)="openConfig()"></p-button>
            <p-button label="Lancer un scan" icon="pi pi-play" [rounded]="true" (click)="triggerScan()"></p-button>
            <p-button icon="pi pi-trash" severity="danger" [rounded]="true" [outlined]="true" (click)="confirmDeleteContainer()"></p-button>
        </div>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="flex flex-column align-items-center justify-content-center p-8">
        <i class="pi pi-spin pi-spinner text-5xl text-primary mb-3"></i>
        <span class="text-secondary font-medium">Récupération des données...</span>
      </div>

      <!-- List View -->
      <div *ngIf="!loading && view === 'list'">
        <div class="card shadow-1 border-round p-0 surface-card overflow-hidden mt-4" *ngIf="containers.length > 0">
          <div class="p-4 border-bottom-1 border-100 flex justify-content-between align-items-center bg-50">
            <div class="flex align-items-center">
              <i class="pi pi-box text-primary mr-2"></i>
              <span class="font-bold text-lg">Liste des conteneurs ({{ containers.length }})</span>
            </div>
            <span class="p-input-icon-left">
              <i class="pi pi-search"></i>
              <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="p-inputtext-sm" />
            </span>
          </div>

          <p-table #dt [value]="containers" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                   [globalFilterFields]="['imageName','registry','tag']"
                   responsiveLayout="scroll" styleClass="p-datatable-sm border-round"
                   [rowHover]="true" (onRowSelect)="showDetails($any($event).data)" selectionMode="single">
            <ng-template pTemplate="header">
              <tr>
                <th pSortableColumn="imageName" style="width: 25%">Image <p-sortIcon field="imageName"></p-sortIcon></th>
                <th pSortableColumn="tag" style="width: 15%">Tag <p-sortIcon field="tag"></p-sortIcon></th>
                <th pSortableColumn="lastScan" style="width: 15%">Dernier Scan <p-sortIcon field="lastScan"></p-sortIcon></th>
                <th class="text-center" style="width: 20%">Vulnérabilités</th>
                <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
              </tr>
            </ng-template>
            <ng-template pTemplate="body" let-container>
              <tr [pSelectableRow]="container" class="cursor-pointer">
                <td>
                  <div class="flex flex-column">
                    <span class="font-semibold text-900">{{ container.imageName }}</span>
                    <span class="text-sm text-500" *ngIf="container.registry">{{ container.registry }}</span>
                  </div>
                </td>
                <td>
                  <p-tag [value]="container.tag" severity="info" [rounded]="true"></p-tag>
                </td>
                <td>
                  <span class="text-sm text-600" *ngIf="container.scans?.length > 0">
                    {{ container.scans[container.scans.length - 1].createdAt | date:'dd/MM/yyyy HH:mm' }}
                  </span>
                  <span class="text-sm text-400 font-italic" *ngIf="!container.scans || container.scans.length === 0">Jamais</span>
                </td>
                <td class="text-center">
                  <div class="flex gap-2 justify-content-center" *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'completed'">
                    <p-tag *ngIf="container.scans[container.scans.length - 1].summary?.critical > 0" severity="danger" [value]="container.scans[container.scans.length - 1].summary.critical.toString()" pTooltip="Critique"></p-tag>
                    <p-tag *ngIf="container.scans[container.scans.length - 1].summary?.high > 0" severity="warn" [value]="container.scans[container.scans.length - 1].summary.high.toString()" pTooltip="Élevé"></p-tag>
                    <p-tag *ngIf="container.scans[container.scans.length - 1].summary?.medium > 0" severity="info" [value]="container.scans[container.scans.length - 1].summary.medium.toString()" pTooltip="Moyen"></p-tag>
                    <span *ngIf="(container.scans[container.scans.length - 1].summary?.critical || 0) === 0 && (container.scans[container.scans.length - 1].summary?.high || 0) === 0 && (container.scans[container.scans.length - 1].summary?.medium || 0) === 0" class="text-500 text-sm">
                      <i class="pi pi-check-circle text-green-500 mr-1"></i> Clean
                    </span>
                  </div>
                  <span class="text-sm text-400 font-italic" *ngIf="!container.scans || container.scans.length === 0 || container.scans[container.scans.length - 1].status !== 'completed'">N/A</span>
                </td>
                <td>
                  <p-tag *ngIf="!container.scans || container.scans.length === 0" value="Aucun scan" severity="secondary" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'completed'" value="Terminé" severity="success" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'failed'" value="Échec" severity="danger" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'pending'" value="En attente" severity="warn" icon="pi pi-clock" [rounded]="true"></p-tag>
                  <p-tag *ngIf="container.scans?.length > 0 && container.scans[container.scans.length - 1].status === 'scanning'" value="En cours" severity="info" icon="pi pi-spin pi-spinner" [rounded]="true"></p-tag>
                </td>
              </tr>
            </ng-template>
            <ng-template pTemplate="emptymessage">
              <tr>
                <td colspan="5" class="text-center p-4">Aucun conteneur trouvé.</td>
              </tr>
            </ng-template>
          </p-table>
        </div>

        <!-- Empty State -->
        <div *ngIf="containers.length === 0" class="flex flex-column align-items-center justify-content-center p-8 text-center bg-white border-round shadow-1 mt-4">
          <div class="surface-100 border-circle p-4 mb-4">
            <i class="pi pi-box text-6xl text-primary"></i>
          </div>
          <h3 class="text-2xl font-bold text-900 mb-2">Aucun conteneur surveillé</h3>
          <p class="text-secondary max-w-20rem mb-4 line-height-3">Ajoutez votre première image Docker pour commencer à l'analyser et détecter les vulnérabilités.</p>
          <p-button label="Ajouter une image" icon="pi pi-plus" [rounded]="true" size="large" routerLink="/add-container"></p-button>
        </div>
      </div>

      <!-- Details View -->
      <div *ngIf="view === 'details' && selectedContainer" class="fadein animation-duration-400">
        <div class="grid">
          <!-- Container Specs Card -->
          <div class="col-12 lg:col-4">
            <div class="card shadow-1 border-round p-4 surface-card h-full">
              <h5 class="text-xl font-bold mb-4 border-bottom-1 border-100 pb-3 flex align-items-center gap-2">
                <i class="pi pi-info-circle text-primary"></i> Configuration
              </h5>
              <div class="flex flex-column gap-4">
                <div class="flex flex-column gap-1">
                  <span class="text-xs font-bold text-500 uppercase">Image</span>
                  <div class="text-900 font-bold text-lg">
                    {{ selectedContainer.imageName }}
                  </div>
                </div>
                <div class="flex flex-column gap-1" *ngIf="selectedContainer.registry">
                  <span class="text-xs font-bold text-500 uppercase">Registre</span>
                  <div class="text-900 font-medium break-all bg-50 p-2 border-round border-1 border-100 text-sm">
                    {{ selectedContainer.registry }}
                  </div>
                </div>
                <div class="grid nogutter">
                  <div class="col-12">
                    <span class="text-xs font-bold text-500 uppercase">Tag</span>
                    <div class="text-900 font-bold mt-1 flex align-items-center gap-2">
                      <p-tag [value]="selectedContainer.tag" severity="info" [rounded]="true"></p-tag>
                    </div>
                  </div>
                </div>
                <div class="flex flex-column gap-1 pt-2 border-top-1 border-100">
                  <span class="text-xs font-bold text-500 uppercase">Planification</span>
                  <div class="flex align-items-center gap-2 mt-1">
                    <p-tag [severity]="(selectedContainer.scanIntervalMinutes || selectedContainer.scanCron) ? 'success' : 'secondary'" 
                           [icon]="(selectedContainer.scanIntervalMinutes || selectedContainer.scanCron) ? 'pi pi-calendar' : 'pi pi-calendar-times'"
                           [value]="(selectedContainer.scanIntervalMinutes || selectedContainer.scanCron) ? 'Configurée' : 'Non planifié'">
                    </p-tag>
                  </div>
                </div>
                <div class="mt-2 pt-4 border-top-1 border-100">
                  <p-button label="Lancer un scan" icon="pi pi-play" styleClass="w-full" (click)="triggerScan()"></p-button>
                </div>
              </div>
            </div>
          </div>

          <!-- History Table Card -->
          <div class="col-12 lg:col-8">
            <div class="card shadow-1 border-round p-0 surface-card overflow-hidden">
              <div class="p-4 border-bottom-1 border-100 flex justify-content-between align-items-center bg-50">
                <div class="flex align-items-center">
                  <i class="pi pi-history text-primary mr-2"></i>
                  <span class="font-bold text-lg">Historique des Scans</span>
                </div>
                <p-tag [value]="(selectedContainer.scans?.length || 0) + ' analyses'" severity="secondary" [rounded]="true"></p-tag>
              </div>
              
              <p-table [value]="selectedContainer.scans" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                       responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true" [sortOrder]="-1" sortField="createdAt">
                <ng-template pTemplate="header">
                  <tr>
                    <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
                    <th style="width: 30%">Vulnérabilités</th>
                    <th pSortableColumn="createdAt" style="width: 25%">Date <p-sortIcon field="createdAt"></p-sortIcon></th>
                    <th pSortableColumn="durationMs" style="width: 15%">Durée <p-sortIcon field="durationMs"></p-sortIcon></th>
                    <th class="text-center" style="width: 15%">Action</th>
                  </tr>
                </ng-template>
                <ng-template pTemplate="body" let-scan>
                  <tr class="hover:surface-50 transition-colors">
                    <td>
                      <p-tag *ngIf="scan.status === 'completed'" value="Terminé" severity="success" [rounded]="true"></p-tag>
                      <p-tag *ngIf="scan.status === 'failed'" value="Échec" severity="danger" [rounded]="true"></p-tag>
                      <p-tag *ngIf="scan.status === 'pending'" value="En attente" severity="warn" icon="pi pi-clock" [rounded]="true"></p-tag>
                      <p-tag *ngIf="scan.status === 'scanning'" value="En cours" severity="info" icon="pi pi-spin pi-spinner" [rounded]="true"></p-tag>
                    </td>
                    <td>
                      <div class="flex gap-1" *ngIf="scan.status === 'completed' && scan.summary">
                         <p-tag *ngIf="scan.summary.critical > 0" severity="danger" [value]="scan.summary.critical.toString()" pTooltip="Critique"></p-tag>
                         <p-tag *ngIf="scan.summary.high > 0" severity="warn" [value]="scan.summary.high.toString()" pTooltip="Élevé"></p-tag>
                         <p-tag *ngIf="scan.summary.medium > 0" severity="info" [value]="scan.summary.medium.toString()" pTooltip="Moyen"></p-tag>
                         <span *ngIf="scan.summary.critical === 0 && scan.summary.high === 0 && scan.summary.medium === 0" class="text-500 text-sm"><i class="pi pi-check text-green-500"></i> Clean</span>
                      </div>
                      <span *ngIf="scan.status !== 'completed'" class="text-500 font-italic">N/A</span>
                    </td>
                    <td class="text-600 text-sm font-medium">
                      {{ scan.createdAt | date:'dd/MM/yyyy HH:mm' }}
                    </td>
                    <td class="text-600 text-sm">
                      <span *ngIf="scan.durationMs">{{ (scan.durationMs / 1000 | number:'1.0-1') }}s</span>
                      <span *ngIf="!scan.durationMs" class="text-400 font-italic">N/A</span>
                    </td>
                    <td>
                      <div class="flex justify-content-center gap-2">
                        <p-button *ngIf="scan.status === 'completed'" icon="pi pi-eye" [text]="true" [rounded]="true" (click)="viewScanDetails(scan)" pTooltip="Voir les détails" size="small"></p-button>
                        <p-button *ngIf="scan.status === 'failed'" icon="pi pi-refresh" [text]="true" [rounded]="true" severity="warn" (click)="relancerScan(scan)" pTooltip="Relancer" size="small"></p-button>
                        <p-button icon="pi pi-trash" [text]="true" [rounded]="true" severity="danger" (click)="confirmDeleteScan(scan)" pTooltip="Supprimer" size="small"></p-button>
                      </div>
                    </td>
                  </tr>
                </ng-template>
                <ng-template pTemplate="emptymessage">
                  <tr>
                    <td colspan="5" class="text-center p-5 text-secondary">
                      <i class="pi pi-info-circle text-4xl block mb-3"></i>
                      Aucun scan dans l'historique de cette image.
                    </td>
                  </tr>
                </ng-template>
              </p-table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <app-scan-details 
      [(display)]="showScanDetails" 
      [scan]="selectedScanForDetails"
      (displayChange)="!$event && closeScanDetails()">
    </app-scan-details>

    <!-- Configuration Dialog -->
    <p-dialog [(visible)]="displayConfig" [modal]="true" header="Configuration du conteneur" [style]="{width: '35rem'}">
      <div class="flex flex-column gap-4 pt-3" *ngIf="selectedContainer">
        
        <div class="flex flex-column gap-2">
          <label class="font-semibold">Mode de planification</label>
          <p-selectButton [options]="scheduleModes" [(ngModel)]="selectedScheduleMode" optionLabel="label" optionValue="value" (onChange)="onScheduleModeChange()"></p-selectButton>
        </div>

        <div class="flex flex-column gap-2" *ngIf="selectedScheduleMode === 'interval'">
          <label class="font-semibold">Intervalle (minutes)</label>
          <div class="p-inputgroup">
            <input pInputText type="number" [(ngModel)]="configInterval" placeholder="Ex: 1440 (24h)" min="0" />
            <span class="p-inputgroup-addon">min</span>
          </div>
          <small class="text-500">Mettez 0 ou laissez vide pour désactiver la planification par intervalle.</small>
        </div>

        <div class="flex flex-column gap-2" *ngIf="selectedScheduleMode === 'cron'">
          <label class="font-semibold">Expression Cron</label>
          <input pInputText [(ngModel)]="configCron" placeholder="Ex: 0 0 * * *" />
          <small class="text-500">Format: minute heure jour mois jour-semaine. Laissez vide pour désactiver.</small>
          <small class="text-primary font-medium mt-1"><i class="pi pi-info-circle mr-1"></i>Ex: "0 2 * * *" (tous les jours à 2h00)</small>
        </div>
        
        <div *ngIf="configError" class="text-red-500 text-sm mt-2">
          {{ configError }}
        </div>
      </div>
      <ng-template pTemplate="footer">
        <p-button label="Annuler" icon="pi pi-times" [outlined]="true" severity="secondary" (click)="displayConfig = false"></p-button>
        <p-button label="Sauvegarder" icon="pi pi-check" (click)="saveConfig()"></p-button>
      </ng-template>
    </p-dialog>
```

### frontend/src/app/dashboard/dashboard.ts
```html
<div class="grid p-fluid">
      <div class="col-12" *ngIf="canManage()">
        <app-add-repo (repoAdded)="fetchRepos()"></app-add-repo>
      </div>

      <div class="col-12" *ngIf="criticalProjects.length > 0">
        <div class="card shadow-1 border-round p-4 surface-card border-left-3 border-red-500 mb-4" style="background: rgba(254, 242, 242, 0.5)">
          <div class="flex align-items-center gap-2 mb-3">
            <i class="pi pi-exclamation-triangle text-red-600 text-2xl"></i>
            <h5 class="m-0 font-bold text-red-900 uppercase tracking-wider">Security Alerts: Critical Vulnerabilities Detected</h5>
          </div>
          <div class="grid">
            <div *ngFor="let item of criticalProjects" class="col-12 md:col-6 lg:col-4">
              <div class="flex align-items-center justify-content-between p-3 border-round bg-white shadow-1 border-1 border-red-100 hover:shadow-2 transition-all transition-duration-200">
                <div class="flex flex-column gap-1 overflow-hidden">
                  <span class="font-bold text-900 white-space-nowrap overflow-hidden text-overflow-ellipsis">{{item.repo.name || (item.repo.url | limitTo: 20)}}</span>
                  <div class="flex align-items-center gap-2">
                    <p-tag [value]="item.criticalCount + ' CRITICAL'" severity="danger" [rounded]="true" styleClass="text-xs font-bold"></p-tag>
                    <span class="text-xs text-500">{{item.repo.branch}}</span>
                  </div>
                </div>
                <p-button icon="pi pi-arrow-right" [text]="true" size="small" (click)="selectScan({repo: item.repo, scan: item.scan})" pTooltip="View Scan Details"></p-button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-12 md:col-6">
        <div class="card shadow-1 border-round p-4 surface-card mb-4 min-h-20rem">
          <h5 class="m-0 font-semibold mb-3">Total Projects</h5>
          <div class="flex flex-column align-items-center justify-content-center h-full pt-4">
            <svg width="200" height="200" viewBox="0 0 200 200" class="project-svg">
              <defs>
                <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" style="stop-color:#6366f1;stop-opacity:1" />
                  <stop offset="100%" style="stop-color:#a855f7;stop-opacity:1" />
                </linearGradient>
                <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur in="SourceAlpha" stdDeviation="3" />
                  <feOffset dx="0" dy="2" result="offsetblur" />
                  <feComponentTransfer>
                    <feFuncA type="linear" slope="0.3" />
                  </feComponentTransfer>
                  <feMerge>
                    <feMergeNode />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>
              <circle cx="100" cy="100" r="80" fill="none" stroke="#f1f5f9" stroke-width="12" />
              <circle cx="100" cy="100" r="80" fill="none" stroke="url(#grad1)" stroke-width="12" 
                      stroke-linecap="round" [attr.stroke-dasharray]="projectCircleDash" 
                      style="transition: stroke-dasharray 0.8s ease-out; transform: rotate(-90deg); transform-origin: 50% 50%;" />
              <text x="100" y="95" text-anchor="middle" font-size="44" font-weight="bold" fill="#1e293b" class="font-sans">
                {{repositories.length}}
              </text>
              <text x="100" y="125" text-anchor="middle" font-size="14" fill="#64748b" font-weight="500">
                PROJETS
              </text>
            </svg>
          </div>
        </div>
      </div>

      <div class="col-12 md:col-6">
        <div class="card shadow-1 border-round p-4 surface-card mb-4 min-h-20rem">
          <h5 class="m-0 font-semibold mb-3">Total Vulnerabilities</h5>
          <div class="flex flex-column md:flex-row align-items-center justify-content-center h-full pt-2">
            <svg width="200" height="200" viewBox="0 0 100 100" class="donut-svg mr-4">
              <circle cx="50" cy="50" r="40" fill="none" stroke="#f1f5f9" stroke-width="10" />
              <ng-container *ngFor="let segment of donutSegments">
                <circle cx="50" cy="50" r="40" fill="none" 
                        [attr.stroke]="segment.color" 
                        stroke-width="10" 
                        [attr.stroke-dasharray]="segment.dashArray" 
                        [attr.stroke-dashoffset]="segment.dashOffset"
                        style="transition: all 0.5s ease-out; transform: rotate(-90deg); transform-origin: 50% 50%;" />
              </ng-container>
              <text x="50" y="47" text-anchor="middle" font-size="16" font-weight="bold" fill="#1e293b">
                {{totalVulnerabilities}}
              </text>
              <text x="50" y="60" text-anchor="middle" font-size="6" fill="#64748b" font-weight="600">
                TOTAL
              </text>
            </svg>
            <div class="flex flex-column gap-2 mt-4 md:mt-0">
               <div *ngFor="let item of vulnerabilityLegend" class="flex align-items-center gap-2">
                  <span [style.background-color]="item.color" class="block border-round" style="width: 12px; height: 12px"></span>
                  <span class="text-sm font-medium text-700">{{item.label}}:</span>
                  <span class="text-sm font-bold text-900">{{item.value}}</span>
               </div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-12">
        <div class="card shadow-1 border-round p-4 surface-card">
          <div class="flex justify-content-between align-items-center mb-4">
            <h5 class="m-0 font-semibold">Repositories & Branch Scans</h5>
            <div class="flex align-items-center gap-3">
               <p class="text-secondary m-0 flex align-items-center gap-2 text-sm">
                <span class="status-dot" [class.online]="isOnline"></span>
                {{ isOnline ? 'Real-time updates enabled' : 'Connecting...' }}
              </p>
              <p-button label="Refresh" icon="pi pi-refresh" [outlined]="true" size="small" (click)="fetchRepos()"></p-button>
            </div>
          </div>
          
          <app-repo-list 
            [repositories]="repositories"
            (viewDetails)="selectScan($event)"
            (rescan)="onRescan($event)">
          </app-repo-list>
        </div>
      </div>

      <app-scan-details 
        [(display)]="displayDetails" 
        [repo]="selectedRepo" 
        [scan]="selectedScan"
        (displayChange)="!$event && closeModal()">
      </app-scan-details>
    </div>
```

### frontend/src/app/depots/depots.ts
```html
<div class="depots-page">
      <!-- Header Section -->
      <div class="flex justify-content-between align-items-center mb-5">
        <div class="flex align-items-center gap-3">
          <p-button *ngIf="view === 'details'" icon="pi pi-arrow-left" [rounded]="true" [text]="true" (click)="goBack()" pTooltip="Retour à la liste"></p-button>
          <div>
            <h2 class="text-3xl font-bold m-0 text-900">{{ view === 'list' ? 'Dépôts' : (selectedRepo?.name || 'Détails du dépôt') }}</h2>
            <p class="text-secondary m-0 mt-1">{{ view === 'list' ? 'Gérez et explorez vos dépôts connectés' : 'Configuration et historique des scans' }}</p>
          </div>
        </div>
        <div class="flex gap-2" *ngIf="view === 'list'">
            <p-button icon="pi pi-refresh" [rounded]="true" [text]="true" (click)="fetchRepositories()" [loading]="loading" pTooltip="Actualiser"></p-button>
            <p-button label="Ajouter un dépôt" icon="pi pi-plus" [rounded]="true" routerLink="/add-repo"></p-button>
        </div>
        <div class="flex gap-2" *ngIf="view === 'details'">
            <p-button label="Configurer" icon="pi pi-cog" [outlined]="true" [rounded]="true" (click)="openConfig()"></p-button>
            <p-button label="Lancer un scan" icon="pi pi-play" [rounded]="true" (click)="triggerScan()"></p-button>
        </div>
      </div>

      <!-- Loading State -->
      <div *ngIf="loading" class="flex flex-column align-items-center justify-content-center p-8">
        <i class="pi pi-spin pi-spinner text-5xl text-primary mb-3"></i>
        <span class="text-secondary font-medium">Récupération des données...</span>
      </div>

      <!-- List View -->
      <div *ngIf="!loading && view === 'list'">
        <div class="card shadow-1 border-round p-0 surface-card overflow-hidden mt-4" *ngIf="repositories.length > 0">
          <div class="p-4 border-bottom-1 border-100 flex justify-content-between align-items-center bg-50">
            <div class="flex align-items-center">
              <i class="pi pi-list text-primary mr-2"></i>
              <span class="font-bold text-lg">Liste des dépôts ({{ repositories.length }})</span>
            </div>
            <span class="p-input-icon-left">
              <i class="pi pi-search"></i>
              <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="p-inputtext-sm" />
            </span>
          </div>

          <p-table #dt [value]="repositories" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                   [globalFilterFields]="['name','url','branch']"
                   responsiveLayout="scroll" styleClass="p-datatable-sm border-round"
                   [rowHover]="true" (onRowSelect)="showDetails($any($event).data)" selectionMode="single">
            <ng-template pTemplate="header">
              <tr>
                <th pSortableColumn="name" style="width: 25%">Dépôt <p-sortIcon field="name"></p-sortIcon></th>
                <th pSortableColumn="branch" style="width: 15%">Branche <p-sortIcon field="branch"></p-sortIcon></th>
                <th pSortableColumn="lastScan" style="width: 15%">Dernier Scan <p-sortIcon field="lastScan"></p-sortIcon></th>
                <th style="width: 10%">Version</th>
                <th class="text-center" style="width: 20%">Vulnérabilités</th>
                <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
              </tr>
            </ng-template>
            <ng-template pTemplate="body" let-repo>
              <tr [pSelectableRow]="repo" class="cursor-pointer">
                <td>
                  <div class="flex align-items-center gap-2">
                    <i class="pi pi-github text-xl text-500"></i>
                    <div class="flex flex-column">
                      <span class="font-bold text-900" *ngIf="repo.name">{{ repo.name }}</span>
                      <span [class]="repo.name ? 'text-xs text-secondary mt-1' : 'font-bold text-900'">{{ repo.url | limitTo:40 }}</span>
                    </div>
                  </div>
                </td>
                <td>
                  <span class="branch-chip">
                    <i class="pi pi-code text-xs"></i> {{ repo.branch }}
                  </span>
                </td>
                <td class="text-sm text-secondary">
                  {{ (getLatestScan(repo)?.createdAt | date:'dd/MM/yy HH:mm') || '—' }}
                </td>
                <td>
                  <p-tag [value]="getLatestScan(repo)?.version || '---'" severity="secondary" [rounded]="true" styleClass="text-xs"></p-tag>
                </td>
                <td class="text-center">
                  <div class="flex gap-1 justify-content-center">
                    <ng-container *ngIf="getLatestScan(repo) as scan">
                      <div class="flex align-items-center gap-1" *ngIf="scan.status === 'completed' && scan.summary; else scanStatus">
                         <ng-container *ngIf="scan.summary.total > 0; else ras">
                            <span class="vuln-chip critical" *ngIf="scan.summary.critical > 0" pTooltip="Critical">{{ scan.summary.critical }}</span>
                            <span class="vuln-chip high"     *ngIf="scan.summary.high > 0"     pTooltip="High">{{ scan.summary.high }}</span>
                            <span class="vuln-chip medium"   *ngIf="scan.summary.medium > 0"   pTooltip="Medium">{{ scan.summary.medium }}</span>
                            <span class="vuln-chip low"      *ngIf="scan.summary.low > 0"      pTooltip="Low">{{ scan.summary.low }}</span>
                         </ng-container>
                         <ng-template #ras><span class="text-xs text-green-600 font-semibold">✓ RAS</span></ng-template>
                      </div>
                      <ng-template #scanStatus>
                        <span class="text-xs text-secondary italic" *ngIf="scan.status !== 'failed'">En cours...</span>
                        <span class="text-xs text-red-500 font-bold" *ngIf="scan.status === 'failed'">Échec</span>
                      </ng-template>
                    </ng-container>
                    <span *ngIf="!getLatestScan(repo)" class="text-xs text-secondary italic">Aucun scan</span>
                  </div>
                </td>
                <td>
                   <div class="status-badge text-xs" [ngClass]="'status-' + (getLatestScan(repo)?.status || 'pending')">
                      <i [class]="getStatusIcon(getLatestScan(repo)?.status)"></i>
                      {{ getStatusLabel(getLatestScan(repo)?.status) }}
                   </div>
                </td>
              </tr>
            </ng-template>
            <ng-template pTemplate="emptymessage">
                <tr>
                    <td colspan="6" class="text-center p-5 text-secondary">
                        <i class="pi pi-search text-4xl block mb-3"></i>
                        Aucun dépôt trouvé correspondant à votre recherche.
                    </td>
                </tr>
            </ng-template>
          </p-table>
        </div>

        <!-- Empty State -->
        <div *ngIf="repositories.length === 0" class="flex flex-column align-items-center justify-content-center p-8 surface-card border-round border-1 border-dashed surface-border mt-4">
          <i class="pi pi-database text-6xl text-200 mb-4"></i>
          <h4 class="m-0 text-secondary">Aucun dépôt configuré</h4>
          <p class="text-secondary mt-2">Connectez votre premier dépôt pour lancer une analyse.</p>
          <p-button label="Connecter un dépôt" icon="pi pi-plus" class="mt-4" [outlined]="true" routerLink="/add-repo"></p-button>
        </div>
      </div>

      <!-- Details View -->
      <div *ngIf="!loading && view === 'details' && selectedRepo" class="fadein animation-duration-400">
        <div class="grid">
          <!-- Repo Specs Card -->
          <div class="col-12 lg:col-4">
            <div class="card shadow-1 border-round p-4 surface-card h-full">
              <h5 class="text-xl font-bold mb-4 border-bottom-1 border-100 pb-3 flex align-items-center gap-2">
                <i class="pi pi-info-circle text-primary"></i> Configuration
              </h5>
              <div class="flex flex-column gap-4">
                <div class="flex flex-column gap-1" *ngIf="selectedRepo.name">
                  <span class="text-xs font-bold text-500 uppercase">Nom du dépôt</span>
                  <div class="text-900 font-bold text-lg">
                    {{ selectedRepo.name }}
                  </div>
                </div>
                <div class="flex flex-column gap-1">
                  <span class="text-xs font-bold text-500 uppercase">URL du dépôt</span>
                  <div class="text-900 font-medium break-all bg-50 p-2 border-round border-1 border-100 text-sm">
                    {{ selectedRepo.url }}
                  </div>
                </div>
                <div class="grid nogutter">
                  <div class="col-6 pr-2">
                    <span class="text-xs font-bold text-500 uppercase">Branche</span>
                    <div class="text-900 font-bold mt-1 flex align-items-center gap-2">
                      <span class="branch-chip"><i class="pi pi-code text-primary"></i> {{ selectedRepo.branch }}</span>
                    </div>
                  </div>
                  <div class="col-6" *ngIf="selectedRepo.subPath">
                    <span class="text-xs font-bold text-500 uppercase">Chemin</span>
                    <div class="text-900 font-bold mt-1 flex align-items-center gap-2">
                      <i class="pi pi-folder text-primary"></i> {{ selectedRepo.subPath }}
                    </div>
                  </div>
                </div>
                <div class="flex flex-column gap-1 pt-2 border-top-1 border-100">
                  <span class="text-xs font-bold text-500 uppercase">Planification</span>
                  <div class="flex align-items-center gap-2 mt-1">
                    <p-tag [severity]="(selectedRepo.scanIntervalMinutes || selectedRepo.scanCron) ? 'success' : 'secondary'" 
                           [icon]="(selectedRepo.scanIntervalMinutes || selectedRepo.scanCron) ? 'pi pi-calendar' : 'pi pi-calendar-times'"
                           [value]="getScheduleLabel(selectedRepo)">
                    </p-tag>
                  </div>
                </div>
                <div class="mt-2 pt-4 border-top-1 border-100">
                  <p-button label="Lancer un scan" icon="pi pi-play" styleClass="w-full" (click)="triggerScan()"></p-button>
                </div>
              </div>
            </div>
          </div>

          <!-- History Table Card -->
          <div class="col-12 lg:col-8">
            <div class="card shadow-1 border-round p-0 surface-card overflow-hidden">
              <div class="p-4 border-bottom-1 border-100 flex justify-content-between align-items-center bg-50">
                <div class="flex align-items-center">
                  <i class="pi pi-history text-primary mr-2"></i>
                  <span class="font-bold text-lg">Historique des Scans</span>
                </div>
                <p-tag [value]="selectedRepo.scans.length + ' analyses'" severity="secondary" [rounded]="true"></p-tag>
              </div>
              
              <p-table [value]="selectedRepo.scans" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
                       responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
                <ng-template pTemplate="header">
                  <tr>
                    <th pSortableColumn="status" style="width: 15%">Statut <p-sortIcon field="status"></p-sortIcon></th>
                    <th style="width: 25%">Vulnérabilités</th>
                    <th pSortableColumn="createdAt" style="width: 20%">Date <p-sortIcon field="createdAt"></p-sortIcon></th>
                    <th pSortableColumn="version" style="width: 15%">Version <p-sortIcon field="version"></p-sortIcon></th>
                    <th pSortableColumn="durationMs" style="width: 15%">Durée <p-sortIcon field="durationMs"></p-sortIcon></th>
                    <th class="text-center" style="width: 10%">Action</th>
                  </tr>
                </ng-template>
                <ng-template pTemplate="body" let-scan>
                  <tr class="hover:surface-50 transition-colors">
                    <td>
                      <span class="status-badge text-xs" [ngClass]="'status-' + scan.status">
                        <i [class]="getStatusIcon(scan.status)"></i>
                        {{ getStatusLabel(scan.status) }}
                      </span>
                    </td>
                    <td>
                      <ng-container *ngIf="scan.status === 'completed' && scan.summary; else noVulns">
                        <div class="flex align-items-center gap-1" *ngIf="scan.summary.total > 0; else ras">
                          <span class="vuln-chip critical" *ngIf="scan.summary.critical > 0" pTooltip="Critical">{{ scan.summary.critical }}</span>
                          <span class="vuln-chip high"     *ngIf="scan.summary.high > 0"     pTooltip="High">{{ scan.summary.high }}</span>
                          <span class="vuln-chip medium"   *ngIf="scan.summary.medium > 0"   pTooltip="Medium">{{ scan.summary.medium }}</span>
                          <span class="vuln-chip low"      *ngIf="scan.summary.low > 0"      pTooltip="Low">{{ scan.summary.low }}</span>
                        </div>
                        <ng-template #ras>
                          <span class="text-xs text-green-600 font-semibold">✓ RAS</span>
                        </ng-template>
                      </ng-container>
                      <ng-template #noVulns>
                        <span class="text-xs text-secondary italic" *ngIf="scan.status !== 'failed'">Analyse en cours...</span>
                        <span class="text-xs text-red-500 font-bold" *ngIf="scan.status === 'failed'">Échec de l'analyse</span>
                      </ng-template>
                    </td>
                    <td class="text-sm font-medium text-secondary">
                      {{ scan.createdAt | date:'dd MMM yyyy, HH:mm' }}
                    </td>
                    <td>
                      <p-tag [value]="scan.version || '---'" severity="secondary" [rounded]="true" styleClass="text-xs"></p-tag>
                    </td>
                    <td class="text-sm text-secondary">
                      {{ scan.durationMs ? (scan.durationMs / 1000 | number:'1.0-0') + 's' : '—' }}
                    </td>
                    <td class="text-center">
                      <div class="flex gap-2 justify-content-center">
                        <p-button icon="pi pi-eye" [text]="true" size="small" severity="info"
                                  pTooltip="Voir les détails"
                                  (click)="showScanDetails(scan)">
                        </p-button>
                        <p-button icon="pi pi-refresh" [text]="true" size="small" severity="secondary"
                                  pTooltip="Relancer"
                                  [disabled]="scan.status === 'scanning' || scan.status === 'pending'"
                                  (click)="relancerScan(scan)">
                        </p-button>
                        <p-button icon="pi pi-trash" [text]="true" size="small" severity="danger"
                                  pTooltip="Supprimer"
                                  [disabled]="scan.status === 'scanning' || scan.status === 'pending'"
                                  (click)="deleteScan(scan)">
                        </p-button>
                      </div>
                    </td>
                  </tr>
                </ng-template>
                <ng-template pTemplate="emptymessage">
                    <tr>
                        <td colspan="6" class="text-center p-5 text-secondary">
                            Aucun scan effectué pour ce dépôt.
                        </td>
                    </tr>
                </ng-template>
              </p-table>
            </div>
          </div>
        </div>
      <!-- Scan Details Modal -->
      <app-scan-details 
        [(display)]="displayDetails" 
        [scan]="selectedScan" 
        [repo]="selectedRepo"
        (displayChange)="!$event && closeModal()">
      </app-scan-details>

      <!-- Configuration Modal -->
      <p-dialog header="Configuration de la planification" [(visible)]="displayConfig" [modal]="true" [style]="{width: '500px'}" [draggable]="false" [resizable]="false">
        <div class="p-fluid">
          <div class="field mb-4 flex justify-content-center">
            <p-selectButton [options]="modeOptions" [(ngModel)]="configMode" optionLabel="label" optionValue="value">
                <ng-template pTemplate="item" let-item>
                    <i [class]="item.icon" class="mr-2"></i>
                    <span>{{item.label}}</span>
                </ng-template>
            </p-selectButton>
          </div>

          <!-- Interval Mode -->
          <div *ngIf="configMode === 'interval'" class="fadein">
            <div class="field mb-4">
              <label class="font-bold block mb-2">Fréquence de scan</label>
              <div class="flex gap-2">
                <div class="flex-grow-1">
                  <input type="number" pInputText [(ngModel)]="configIntervalValue" placeholder="Valeur" min="0" class="w-full" />
                </div>
                <div style="width: 140px">
                  <p-select [options]="unitOptions" [(ngModel)]="configIntervalUnit" optionLabel="label" optionValue="value" class="w-full"></p-select>
                </div>
              </div>
              <small class="text-secondary mt-2 block">Exemple: Toutes les 2 heures.</small>
            </div>
          </div>

          <!-- Cron Mode -->
          <div *ngIf="configMode === 'cron'" class="fadein">
            <div class="field mb-4">
              <label for="cron" class="font-bold block mb-2">Expression Cron</label>
              <div class="p-inputgroup">
                <span class="p-inputgroup-addon"><i class="pi pi-code"></i></span>
                <input type="text" pInputText id="cron" [(ngModel)]="configCron" placeholder="* * * * *" />
              </div>
              <div class="mt-2 flex justify-content-between align-items-center">
                <small class="text-secondary">Standard: minute heure jour mois jour-semaine</small>
                <a href="https://crontab.guru" target="_blank" class="text-xs no-underline text-primary font-bold">
                  Aide (crontab.guru) <i class="pi pi-external-link text-xs"></i>
                </a>
              </div>
            </div>
          </div>

          <div class="p-3 bg-blue-50 border-round text-blue-700 text-sm mb-4">
             <i class="pi pi-info-circle mr-2"></i>
             Laissez vide ou mettez 0 pour désactiver le scan automatique.
          </div>
        </div>
        <ng-template pTemplate="footer">
          <p-button label="Annuler" icon="pi pi-times" [text]="true" (click)="displayConfig = false"></p-button>
          <p-button label="Enregistrer" icon="pi pi-check" (click)="saveConfig()"></p-button>
        </ng-template>
      </p-dialog>
      
      <p-toast></p-toast>
      <p-confirmDialog></p-confirmDialog>
    </div>
```

### frontend/src/app/layout/component/app.footer.ts
```html
<div class="layout-footer">
      <span class="font-medium ml-2">Zanshin - Git Security Scanner</span>
    </div>
```

### frontend/src/app/layout/component/app.layout.ts
```html
<div class="layout-wrapper" [ngClass]="containerClass">
      <app-topbar></app-topbar>
      <app-sidebar></app-sidebar>
      <div class="layout-main-container">
        <div class="layout-main">
          <router-outlet></router-outlet>
        </div>
        <app-footer></app-footer>
      </div>
      <div class="layout-mask"></div>
    </div>
```

### frontend/src/app/layout/component/app.menu.ts
```html
<ul class="layout-menu">
      <ng-container *ngFor="let item of model; let i = index">
        <li app-menuitem *ngIf="!item.separator" [item]="item" [index]="i" [root]="true"></li>
        <li *ngIf="item.separator" class="menu-separator"></li>
      </ng-container>
    </ul>
```

### frontend/src/app/layout/component/app.menuitem.ts
```html
<ng-container>
      <div *ngIf="root && item.visible !== false" class="layout-menuitem-roottext">{{ item.label }}</div>
      <a
        *ngIf="(!item.routerLink || item.items) && item.visible !== false"
        [attr.href]="item.url"
        (click)="itemClick($event)"
        [ngClass]="item.class"
        [attr.target]="item.target"
        tabindex="0"
        pRipple
      >
        <i [ngClass]="item.icon" class="layout-menuitem-icon"></i>
        <span class="layout-menuitem-text">{{ item.label }}</span>
        <i class="pi pi-fw pi-angle-down layout-submenu-toggler" *ngIf="item.items"></i>
      </a>
      <a
        *ngIf="item.routerLink && !item.items && item.visible !== false"
        (click)="itemClick($event)"
        [ngClass]="item.class"
        [routerLink]="item.routerLink"
        routerLinkActive="active-route"
        [routerLinkActiveOptions]="item.routerLinkActiveOptions || { paths: 'exact', queryParams: 'ignored', matrixParams: 'ignored', fragment: 'ignored' }"
        [attr.target]="item.target"
        tabindex="0"
        pRipple
      >
        <i [ngClass]="item.icon" class="layout-menuitem-icon"></i>
        <span class="layout-menuitem-text">{{ item.label }}</span>
        <i class="pi pi-fw pi-angle-down layout-submenu-toggler" *ngIf="item.items"></i>
      </a>

      <ul *ngIf="item.items && item.visible !== false" [@children]="submenuAnimation">
        <ng-container *ngFor="let child of item.items; let i = index">
          <li app-menuitem [item]="child" [index]="i" [parentKey]="key" [root]="false"></li>
        </ng-container>
      </ul>
    </ng-container>
```

### frontend/src/app/layout/component/app.sidebar.ts
```html
<div class="layout-sidebar">
      <app-menu></app-menu>
    </div>
```

### frontend/src/app/layout/component/app.topbar.ts
```html
<div class="layout-topbar">
      <div class="layout-topbar-start">
        <button #menubutton class="p-link layout-menu-button layout-topbar-button" (click)="onMenuToggle()">
          <i class="pi pi-bars"></i>
        </button>

        <a class="layout-topbar-logo ml-4" routerLink="/">
          <i class="pi pi-shield text-primary mr-2" style="font-size: 1.5rem"></i>
          <span class="font-bold text-900" style="font-size: 1.5rem">Zanshin</span>
        </a>
      </div>

      <div class="layout-topbar-end">
        <button #topbarmenubutton class="p-link layout-topbar-menu-button layout-topbar-button" (click)="onTopbarMenuToggle()">
          <i class="pi pi-ellipsis-v"></i>
        </button>

        <div #topbarmenu class="layout-topbar-menu" [ngClass]="{ 'layout-topbar-menu-mobile-active': layoutService.state().profileSidebarActive }">
          <button class="p-link layout-topbar-button" (click)="toggleDarkMode()">
            <i class="pi" [ngClass]="{'pi-moon': !layoutService.isDarkTheme(), 'pi-sun': layoutService.isDarkTheme()}"></i>
            <span>Theme</span>
          </button>
          
          <ng-container *ngIf="authService.user() as user">
            <div class="flex align-items-center gap-2 px-3 border-left-1 border-300">
                <img [src]="user.avatarUrl" *ngIf="user.avatarUrl" [alt]="user.username" class="border-circle" style="width: 32px; height: 32px;">
                <div class="flex flex-column">
                  <span class="font-medium hidden md:block line-height-1">{{ user.displayName || user.username }}</span>
                  <span class="text-xs font-bold px-2 py-0 border-round uppercase w-fit" 
                        [ngClass]="getRoleClass(user.role)">
                    {{ user.role }}
                  </span>
                </div>
            </div>
          </ng-container>

          <button class="p-link layout-topbar-button" (click)="logout()">
            <i class="pi pi-sign-out"></i>
            <span>Déconnexion</span>
          </button>
        </div>
      </div>
    </div>
```

### frontend/src/app/repo-list/repo-list.ts
```html
<div class="repo-list">
      <p-dataView [value]="repositories" [rows]="10" [paginator]="repositories.length > 10">
        <ng-template #list let-items>
          <div class="grid grid-nogutter">
            <div class="col-12" *ngFor="let repo of items; let first = first">
              <div class="p-4 border-1 surface-border surface-card mb-3 border-round shadow-1">
                <div class="flex flex-column sm:flex-row sm:align-items-center gap-3">
                  <div class="flex-1">
                    <div class="flex align-items-center gap-2 mb-2">
                       <i class="pi pi-github text-xl"></i>
                       <span class="text-xl font-bold">{{ repo.name || repo.url }}</span>
                       <span class="text-secondary text-sm ml-2" *ngIf="repo.name">({{ repo.url }})</span>
                       <div class="ml-auto flex flex-column align-items-end">
                         <span class="text-secondary text-xs font-medium">Branche: <span class="text-primary">{{ repo.branch }}</span></span>
                         <span class="text-secondary text-xs font-medium" *ngIf="repo.subPath">Chemin: <span class="text-primary">{{ repo.subPath }}</span></span>
                       </div>
                    </div>

                    <div class="mt-4">
                      <div class="flex align-items-center gap-2 mb-3">
                         <i class="pi pi-history text-secondary"></i>
                         <span class="font-bold">Historique des scans</span>
                         <span class="text-sm text-secondary ml-auto mr-3" *ngIf="repo.scans?.length > 1">{{ repo.scans.length }} scans</span>
                          <p-button icon="pi pi-refresh" [rounded]="true" [text]="true" severity="secondary" size="small"
                                    pTooltip="Relancer le scan"
                                    *ngIf="canManage()"
                                    (onClick)="$event.stopPropagation(); rescan.emit({repoId: repo.id, branch: repo.branch, subPath: repo.subPath})">
                          </p-button>
                      </div>

                      <div class="scan-history border-1 surface-border border-round overflow-hidden">
                        <div class="flex flex-column">
                          <div *ngFor="let scan of repo.scans; let j = index"
                               class="scan-row flex justify-content-between align-items-center p-3 border-bottom-1 surface-border hover:surface-100 cursor-pointer transition-colors transition-duration-200"
                               [class.bg-blue-50]="j === 0"
                               [class.border-bottom-none]="j === repo.scans.length - 1"
                               (click)="viewDetails.emit({repo, scan})">
                            <div class="flex align-items-center gap-3">
                              <span class="text-sm font-medium text-secondary">{{ scan.createdAt | date:'dd/MM/yy HH:mm' }}</span>
                              <span *ngIf="j === 0" class="text-xs font-bold px-2 py-1 bg-primary-100 text-primary-700 border-round">DERNIER</span>
                              
                              <span class="status-badge" [ngClass]="'status-' + scan.status">
                                <i [class]="getStatusIcon(scan.status)"></i>
                                {{ getStatusLabel(scan.status) }}
                              </span>
                            </div>
                            <div class="flex align-items-center gap-3">
                              <ng-container *ngIf="scan.status === 'completed' && scan.summary">
                                <div class="flex gap-1">
                                  <p-tag [value]="scan.summary.critical.toString()" severity="danger" icon="pi pi-exclamation-triangle" *ngIf="scan.summary.critical > 0"></p-tag>
                                  <p-tag [value]="scan.summary.high.toString()" severity="warn" icon="pi pi-exclamation-circle" *ngIf="scan.summary.high > 0"></p-tag>
                                  <p-tag [value]="scan.summary.medium.toString()" severity="info" *ngIf="scan.summary.medium > 0"></p-tag>
                                </div>
                              </ng-container>
                              <span *ngIf="scan.status === 'failed'" class="text-xs text-red-500" pTooltip="Voir l'erreur">
                                <i class="pi pi-info-circle"></i>
                              </span>
                              <i class="pi pi-chevron-right text-secondary"></i>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </ng-template>
      </p-dataView>

      <div *ngIf="repositories.length === 0" class="flex flex-column align-items-center justify-content-center p-8 surface-card border-round border-1 border-dashed surface-border">
        <i class="pi pi-cloud-upload text-6xl text-secondary mb-4"></i>
        <h4 class="m-0 text-secondary">Aucun dépôt ajouté</h4>
        <p class="text-secondary mt-2">Connectez un nouveau dépôt pour démarrer une analyse de vulnérabilités.</p>
      </div>
    </div>
```

### frontend/src/app/scan-center/scan-center.ts
```html
<div class="scan-center p-4">

      <!-- Header -->
      <div class="flex align-items-center justify-content-between mb-5">
        <div>
          <h2 class="m-0 text-2xl font-bold">Centre de scan</h2>
          <p class="text-secondary mt-1 mb-0">Lancez des analyses et consultez l'historique par dépôt et branche</p>
        </div>
        <div class="flex align-items-center gap-2">
          <span class="status-dot" [class.online]="isOnline"></span>
          <span class="text-sm text-secondary">{{ isOnline ? 'Temps réel activé' : 'Connexion...' }}</span>
          <p-button icon="pi pi-refresh" [outlined]="true" size="small" pTooltip="Actualiser" (click)="fetchRepos()"></p-button>
        </div>
      </div>

      <!-- ═══════════════════════════════════════════════════════════ -->
      <!-- TABLEAU 1 : REPOS (lancement de scan)                      -->
      <!-- ═══════════════════════════════════════════════════════════ -->
      <div class="card-section mb-5">
        <div class="section-header mb-3 flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center gap-3">
          <div class="flex align-items-center">
            <i class="pi pi-list text-primary mr-2"></i>
            <span class="font-bold text-lg">Dépôts ({{ repoRows.length }})</span>
          </div>
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dtRepos.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto" />
          </span>
        </div>

        <p-table #dtRepos [value]="repoRows" [loading]="loading" styleClass="p-datatable-sm border-round"
                 [rowHover]="true" responsiveLayout="scroll"
                 [paginator]="true" [rows]="10" [rowsPerPageOptions]="[5, 10, 25, 50]"
                 [globalFilterFields]="['repo.url', 'repo.name', 'branch']">
          <ng-template pTemplate="header">
            <tr>
              <th pSortableColumn="repo.id" style="width:3rem"># <p-sortIcon field="repo.id"></p-sortIcon></th>
              <th pSortableColumn="repo.url">Nom / URL du dépôt <p-sortIcon field="repo.url"></p-sortIcon></th>
              <th style="width:160px">Clé SSH</th>
              <th pSortableColumn="repo.branch" style="width:160px">Branche <p-sortIcon field="repo.branch"></p-sortIcon></th>
              <th style="width:180px">Actions</th>
            </tr>
          </ng-template>

          <ng-template pTemplate="body" let-row>
            <tr>
              <td class="text-secondary text-sm">{{ row.repo.id }}</td>
              <td>
                 <div class="flex align-items-center gap-2">
                  <i class="pi pi-github text-secondary"></i>
                  <div class="flex flex-column">
                    <span class="font-bold text-sm" *ngIf="row.repo.name">{{ row.repo.name }}</span>
                    <span class="text-secondary text-xs" [class.font-medium]="!row.repo.name" [pTooltip]="row.repo.url" tooltipPosition="top">
                      {{ row.repo.url | truncateUrl }}
                    </span>
                  </div>
                </div>
              </td>
              <td>
                <span *ngIf="row.repo.sshKeyId" class="ssh-chip">
                  <i class="pi pi-key text-xs"></i> SSH
                </span>
                <span *ngIf="!row.repo.sshKeyId" class="text-secondary text-xs">HTTPS</span>
              </td>
              <td>
                <span class="branch-chip">
                  <i class="pi pi-code text-xs"></i> {{ row.repo.branch }}
                </span>
              </td>
              <td>
                <div class="flex gap-2">
                  <p-button
                    label="Lancer"
                    icon="pi pi-play"
                    size="small"
                    [loading]="row.isLaunching"
                    [disabled]="isRepoScanning(row.repo)"
                    (click)="launchScan(row)">
                  </p-button>
                  <p-button
                    icon="pi pi-trash"
                    size="small"
                    severity="danger"
                    [outlined]="true"
                    pTooltip="Supprimer"
                    (click)="deleteRepo(row.repo)">
                  </p-button>
                </div>
              </td>
            </tr>
          </ng-template>

          <ng-template pTemplate="emptymessage">
            <tr>
              <td colspan="5" class="text-center p-5 text-secondary">
                <i class="pi pi-inbox text-4xl block mb-3"></i>
                Aucun dépôt. Ajoutez-en un via "Ajouter un dépôt".
              </td>
            </tr>
          </ng-template>
        </p-table>
      </div>

      <!-- ═══════════════════════════════════════════════════════════ -->
      <!-- TABLEAU 2 : SCANS (historique)                             -->
      <!-- ═══════════════════════════════════════════════════════════ -->
      <div class="card-section">
        <div class="section-header mb-3 flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center gap-3">
          <div class="flex align-items-center">
            <i class="pi pi-history text-primary mr-2"></i>
            <span class="font-bold text-lg">Historique des scans ({{ flatScans.length }})</span>
          </div>
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dtScans.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto" />
          </span>
        </div>

        <p-table #dtScans [value]="flatScans" [loading]="loading" styleClass="p-datatable-sm border-round"
                 [rowHover]="true" responsiveLayout="scroll"
                 [paginator]="true" [rows]="10" [rowsPerPageOptions]="[5, 10, 25, 50]"
                 [globalFilterFields]="['repoUrl', 'repoName', 'branch', 'status']">
          <ng-template pTemplate="header">
            <tr>
              <th pSortableColumn="id" style="width:3rem"># <p-sortIcon field="id"></p-sortIcon></th>
              <th pSortableColumn="repoUrl">Dépôt (Nom/URL) <p-sortIcon field="repoUrl"></p-sortIcon></th>
              <th pSortableColumn="branch" style="width:140px">Branche <p-sortIcon field="branch"></p-sortIcon></th>
              <th pSortableColumn="status" style="width:130px">Statut <p-sortIcon field="status"></p-sortIcon></th>
              <th style="width:200px">Vulnérabilités</th>
              <th pSortableColumn="createdAt" style="width:160px">Date <p-sortIcon field="createdAt"></p-sortIcon></th>
              <th pSortableColumn="durationMs" style="width:100px">Durée <p-sortIcon field="durationMs"></p-sortIcon></th>
              <th style="width:110px">Actions</th>
            </tr>
          </ng-template>

          <ng-template pTemplate="body" let-scan>
            <tr>
              <td class="text-secondary text-sm">{{ scan.id }}</td>
              <td>
                 <div class="flex flex-column">
                  <span class="font-bold text-sm" *ngIf="scan.repoName">{{ scan.repoName }}</span>
                  <span class="text-secondary text-xs" [pTooltip]="scan.repoUrl">
                    {{ scan.repoUrl | truncateUrl }}
                  </span>
                </div>
              </td>
              <td>
                <span class="branch-chip">
                  <i class="pi pi-code text-xs"></i> {{ scan.branch }}
                </span>
              </td>
              <td>
                <span class="status-badge" [ngClass]="'status-' + scan.status">
                  <i [class]="getStatusIcon(scan.status)"></i>
                  {{ getStatusLabel(scan.status) }}
                </span>
              </td>
              <td>
                <ng-container *ngIf="scan.status === 'completed' && scan.summary">
                  <div class="flex align-items-center gap-1" *ngIf="scan.summary.total > 0; else noVulns">
                    <span class="vuln-chip critical" *ngIf="scan.summary.critical > 0" pTooltip="Critical">{{ scan.summary.critical }}</span>
                    <span class="vuln-chip high"     *ngIf="scan.summary.high > 0"     pTooltip="High">{{ scan.summary.high }}</span>
                    <span class="vuln-chip medium"   *ngIf="scan.summary.medium > 0"   pTooltip="Medium">{{ scan.summary.medium }}</span>
                    <span class="vuln-chip low"      *ngIf="scan.summary.low > 0"      pTooltip="Low">{{ scan.summary.low }}</span>
                    <span class="text-xs text-secondary ml-1">/ {{ scan.summary.total }}</span>
                  </div>
                  <ng-template #noVulns>
                    <span class="text-xs text-green-600 font-semibold">✓ Aucune</span>
                  </ng-template>
                </ng-container>
                <span *ngIf="scan.status === 'failed'" class="text-xs text-red-500">
                  <i class="pi pi-exclamation-triangle mr-1"></i>Échec
                </span>
                <span *ngIf="scan.status === 'scanning' || scan.status === 'pending'" class="text-xs text-secondary">
                  En cours...
                </span>
              </td>
              <td class="text-sm text-secondary">{{ scan.createdAt | date:'dd/MM/yy HH:mm' }}</td>
              <td class="text-sm text-secondary">
                {{ scan.durationMs ? (scan.durationMs / 1000 | number:'1.0-0') + 's' : '—' }}
              </td>
              <td>
                <div class="flex gap-2">
                  <p-button icon="pi pi-eye" [text]="true" size="small" severity="info"
                            pTooltip="Voir les détails"
                            (click)="viewDetails(scan)">
                  </p-button>
                  <p-button icon="pi pi-refresh" [text]="true" size="small" severity="secondary"
                            pTooltip="Relancer"
                            [disabled]="scan.status === 'scanning' || scan.status === 'pending'"
                            (click)="relancerScan(scan.repoId, scan.branch)">
                  </p-button>
                  <p-button icon="pi pi-trash" [text]="true" size="small" severity="danger"
                            pTooltip="Supprimer"
                            [disabled]="scan.status === 'scanning' || scan.status === 'pending'"
                            (click)="deleteScan(scan)">
                  </p-button>
                </div>
              </td>
            </tr>
          </ng-template>

          <ng-template pTemplate="emptymessage">
            <tr>
              <td colspan="8" class="text-center p-5 text-secondary">
                <i class="pi pi-search text-4xl block mb-3"></i>
                Aucun scan trouvé. Lancez une analyse depuis le tableau ci-dessus.
              </td>
            </tr>
          </ng-template>
        </p-table>
      </div>
    </div>

    <app-scan-details 
      [(display)]="displayDetails" 
      [repo]="selectedRepo" 
      [scan]="selectedScan"
      (displayChange)="!$event && closeModal()">
    </app-scan-details>

    <p-toast position="bottom-right"></p-toast>
    <p-confirmDialog [style]="{width: '450px'}" acceptButtonStyleClass="p-button-danger" rejectButtonStyleClass="p-button-text p-button-secondary"></p-confirmDialog>
```

### frontend/src/app/scan-details/scan-details.ts
```html
<p-dialog 
      [(visible)]="display" 
      [modal]="true" 
      [header]="repo?.url || 'Scan Details'"
      [style]="{ width: '80vw' }" 
      [breakpoints]="{ '960px': '95vw' }"
      [draggable]="false" 
      [resizable]="false"
      appendTo="body"
      (onHide)="closeModal()">
      
      <div *ngIf="scan" class="p-fluid mt-2">
        <div class="flex flex-column md:flex-row justify-content-between align-items-start md:align-items-center mb-4 gap-2">
          <div>
            <div class="flex align-items-center gap-3 mb-1">
              <p class="text-secondary mb-0">Branch: <span class="text-primary font-bold">{{ scan.branch }}</span></p>
              <p class="text-secondary mb-0" *ngIf="scan.version">Version: <span class="bg-blue-50 text-blue-700 px-2 py-1 border-round text-xs font-bold">{{ scan.version }}</span></p>
              <p class="text-secondary mb-0" *ngIf="scan.projectType">Type: <span class="bg-gray-100 text-gray-700 px-2 py-1 border-round text-xs font-bold">{{ scan.projectType }}</span></p>
            </div>
            <p class="text-secondary mb-0" *ngIf="scan.subPath">Path: <span class="text-primary font-bold">{{ scan.subPath }}</span></p>
          </div>
          <div class="flex flex-wrap gap-2">
            <p-button label="Export OpenVEX" icon="pi pi-download" severity="secondary" size="small" (click)="exportVex()" *ngIf="repo"></p-button>
            <p-button label="Download PDF" icon="pi pi-file-pdf" severity="success" size="small" (click)="downloadReport()" *ngIf="scan.status === 'completed'"></p-button>
            <p-button label="Download SBOM" icon="pi pi-download" severity="info" size="small" (click)="downloadJson(scan.sbom, 'sbom.json')" *ngIf="scan.sbom"></p-button>
            <p-button label="Download CVEs" icon="pi pi-download" severity="warn" size="small" (click)="downloadJson(scan.cves, 'cves.json')" *ngIf="scan.cves"></p-button>
          </div>
        </div>

        <p-tabs value="0">
          <p-tablist>
            <p-tab value="0">Summary</p-tab>
            <p-tab value="1">Findings ({{ scan.findingsCount || 0 }})</p-tab>
            <p-tab value="4">Dependencies ({{ artifacts.length }})</p-tab>
            <p-tab value="2">Grype (CVEs)</p-tab>
            <p-tab value="3">Syft (SBOM)</p-tab>
          </p-tablist>
          <p-tabpanels>
            <p-tabpanel value="0">
              <div class="grid text-center mt-3" *ngIf="scan.summary">
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-red-50">
                    <span class="text-4xl font-bold text-red-600 block mb-2">{{ scan.summary.critical }}</span>
                    <span class="text-red-500 font-semibold uppercase text-xs">Critical</span>
                  </div>
                </div>
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-orange-50">
                    <span class="text-4xl font-bold text-orange-600 block mb-2">{{ scan.summary.high }}</span>
                    <span class="text-orange-500 font-semibold uppercase text-xs">High</span>
                  </div>
                </div>
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-yellow-50">
                    <span class="text-4xl font-bold text-yellow-600 block mb-2">{{ scan.summary.medium }}</span>
                    <span class="text-yellow-500 font-semibold uppercase text-xs">Medium</span>
                  </div>
                </div>
                <div class="col-12 md:col-3">
                  <div class="p-3 border-round-xl surface-border border-1 bg-blue-50">
                    <span class="text-4xl font-bold text-blue-600 block mb-2">{{ scan.summary.low }}</span>
                    <span class="text-blue-500 font-semibold uppercase text-xs">Low</span>
                  </div>
                </div>
              </div>
              
              <div class="mt-4" *ngIf="scan.summary">
                <h6 class="font-bold text-lg mb-2">Quick Overview</h6>
                <p class="m-0">This branch analysis contains <strong>{{ scan.findingsCount || 0 }}</strong> total vulnerabilities.</p>
                <p *ngIf="scan.durationMs" class="text-secondary text-sm mt-3">Scan completed in {{ (scan.durationMs / 1000).toFixed(2) }} seconds.</p>
              </div>
            </p-tabpanel>
            
            <p-tabpanel value="1">
              <div class="mt-3">
                <app-vulnerability-table [cves]="scan.cves" [repositoryId]="repo?.id!"></app-vulnerability-table>
              </div>
            </p-tabpanel>

            <p-tabpanel value="4">
              <div class="mt-3">
                <p-table #dtDeps [value]="artifacts" [paginator]="true" [rows]="10" 
                         [rowsPerPageOptions]="[10, 25, 50, 100]"
                         styleClass="p-datatable-sm border-round"
                         [globalFilterFields]="['name', 'version', 'type', 'language']"
                         responsiveLayout="scroll" [rowHover]="true">
                  <ng-template pTemplate="caption">
                    <div class="flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center gap-3 p-1">
                      <div class="flex align-items-center">
                        <i class="pi pi-box text-primary mr-2"></i>
                        <span class="font-bold text-lg text-900">Dépendances découvertes ({{ artifacts.length }})</span>
                      </div>
                      <span class="p-input-icon-left w-full sm:w-auto">
                        <i class="pi pi-search"></i>
                        <input pInputText type="text" (input)="dtDeps.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher un paquet..." class="p-inputtext-sm w-full" />
                      </span>
                    </div>
                  </ng-template>
                  <ng-template pTemplate="header">
                    <tr>
                      <th pSortableColumn="name">Nom / Paquet <p-sortIcon field="name"></p-sortIcon></th>
                      <th pSortableColumn="version" style="width: 20%">Version <p-sortIcon field="version"></p-sortIcon></th>
                      <th pSortableColumn="type" style="width: 150px">Type <p-sortIcon field="type"></p-sortIcon></th>
                      <th pSortableColumn="language" style="width: 150px">Langage <p-sortIcon field="language"></p-sortIcon></th>
                    </tr>
                  </ng-template>
                  <ng-template pTemplate="body" let-pkg>
                    <tr class="hover:surface-50 transition-colors">
                      <td>
                        <div class="flex align-items-center gap-2">
                          <i class="pi pi-package text-secondary"></i>
                          <span class="font-bold text-900">{{ pkg.name }}</span>
                        </div>
                      </td>
                      <td><code class="text-xs surface-100 p-1 border-round">{{ pkg.version }}</code></td>
                      <td>
                        <span class="text-xs px-2 py-1 surface-200 border-round font-medium uppercase">{{ pkg.type }}</span>
                      </td>
                      <td>
                        <p-tag [value]="pkg.language || '—'" severity="secondary" [rounded]="true" styleClass="text-xs"></p-tag>
                      </td>
                    </tr>
                  </ng-template>
                  <ng-template pTemplate="emptymessage">
                    <tr>
                      <td colspan="4" class="text-center p-5 text-secondary">
                        <i class="pi pi-search text-4xl block mb-3"></i>
                        Aucune dépendance trouvée correspondant à votre recherche.
                      </td>
                    </tr>
                  </ng-template>
                </p-table>
              </div>
            </p-tabpanel>

            <p-tabpanel value="2">
              <pre class="bg-gray-900 p-3 border-round text-blue-400 overflow-auto mt-3" style="max-height: 400px;">{{ getJson(scan.cves) }}</pre>
            </p-tabpanel>
            
            <p-tabpanel value="3">
              <pre class="bg-gray-900 p-3 border-round text-purple-400 overflow-auto mt-3" style="max-height: 400px;">{{ getJson(scan.sbom) }}</pre>
            </p-tabpanel>
          </p-tabpanels>
        </p-tabs>
      </div>
    </p-dialog>
```

### frontend/src/app/ssh-keys/ssh-keys.ts
```html
<div class="card shadow-1 border-round p-4 surface-card">
      <div class="flex flex-column sm:flex-row justify-content-between align-items-start sm:align-items-center mb-4 gap-3">
        <div>
          <h2 class="text-2xl font-bold m-0 text-900">Clés SSH</h2>
          <p class="text-secondary mt-1">Gérez les clés de déploiement pour accéder aux dépôts privés</p>
        </div>
        <div class="flex align-items-center gap-3 w-full sm:w-auto">
          <span class="p-input-icon-left w-full sm:w-auto">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto p-inputtext-sm" />
          </span>
          <p-button label="Ajouter" icon="pi pi-plus" (onClick)="showDialog()" size="small"></p-button>
        </div>
      </div>

      <p-table #dt [value]="keys" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
               [globalFilterFields]="['name', 'id', 'publicKey']"
               responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
        <ng-template pTemplate="header">
          <tr>
            <th pSortableColumn="name">Nom <p-sortIcon field="name"></p-sortIcon></th>
            <th pSortableColumn="id" style="width: 25%">ID / Référence <p-sortIcon field="id"></p-sortIcon></th>
            <th>Clé Publique (GitHub/GitLab)</th>
            <th pSortableColumn="createdAt" style="width: 15%">Créée le <p-sortIcon field="createdAt"></p-sortIcon></th>
            <th class="text-center" style="width: 100px">Actions</th>
          </tr>
        </ng-template>
        <ng-template pTemplate="body" let-key>
          <tr class="hover:surface-50 transition-colors">
            <td>
              <div class="flex align-items-center gap-2">
                <i class="pi pi-key text-primary"></i>
                <span class="font-bold text-900">{{key.name}}</span>
              </div>
            </td>
            <td>
              <div class="flex align-items-center gap-2">
                <code class="text-xs surface-100 p-1 border-round text-blue-700 border-1 border-200">{{key.id}}</code>
                <p-button icon="pi pi-copy" size="small" [text]="true" (onClick)="copyToClipboard(key.id)" pTooltip="Copier l'ID"></p-button>
              </div>
            </td>
            <td>
              <div class="flex align-items-center gap-2" *ngIf="key.publicKey">
                <code class="text-xs surface-100 p-1 border-round text-600 border-1 border-200 block text-overflow-ellipsis overflow-hidden white-space-nowrap" style="max-width: 150px">
                  {{key.publicKey}}
                </code>
                <p-button icon="pi pi-copy" size="small" [text]="true" (onClick)="copyToClipboard(key.publicKey)" pTooltip="Copier la clé publique"></p-button>
              </div>
              <span *ngIf="!key.publicKey" class="text-400 italic text-xs">Indisponible</span>
            </td>
            <td class="text-sm text-secondary">{{key.createdAt | date:'dd/MM/yyyy HH:mm'}}</td>
            <td class="text-center">
              <p-button icon="pi pi-trash" severity="danger" [text]="true" size="small" (onClick)="confirmDelete(key)" pTooltip="Supprimer"></p-button>
            </td>
          </tr>
        </ng-template>
        <ng-template pTemplate="emptymessage">
          <tr>
            <td colspan="5" class="text-center p-5 text-secondary">
              <i class="pi pi-shield text-4xl block mb-3"></i>
              Aucune clé SSH trouvée.
            </td>
          </tr>
        </ng-template>
      </p-table>
    </div>

    <!-- Add Key Dialog -->
    <p-dialog [(visible)]="displayDialog" [header]="'Ajouter une clé SSH'" [modal]="true" [style]="{width: '500px'}" [draggable]="false" [resizable]="false" styleClass="border-round-xl">
      <div class="p-fluid">
        <div class="field mb-3">
          <label for="name" class="font-bold block mb-2 text-900">Nom de la clé</label>
          <input pInputText id="name" type="text" [(ngModel)]="newKey.name" placeholder="e.g., Jenkins Production" />
        </div>
        <div class="field mb-3">
          <label for="uuid" class="font-bold block mb-2 text-900">ID / Référence API <span class="text-400 font-normal">(Optionnel)</span></label>
          <div class="p-inputgroup">
            <span class="p-inputgroup-addon"><i class="pi pi-id-card"></i></span>
            <input pInputText id="uuid" type="text" [(ngModel)]="newKey.id" placeholder="Ex: custom-jenkins-id" />
          </div>
          <small class="text-secondary">Utile pour référencer cette clé dans vos automates.</small>
        </div>
        <div class="field mb-3">
          <div class="flex justify-content-between align-items-center mb-2">
            <label for="privateKey" class="font-bold text-900 m-0">Clé Privée <span class="text-400 font-normal text-xs">(format PEM)</span></label>
            <p-button label="Générer" icon="pi pi-refresh" size="small" [text]="true" (onClick)="generateKey()" [loading]="isGenerating"></p-button>
          </div>
          <textarea pTextarea id="privateKey" [(ngModel)]="newKey.privateKey" rows="8" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..." class="text-xs"></textarea>
          <small class="text-secondary">Chiffrée sur le serveur. La clé publique sera extraite.</small>
        </div>
        <div class="field mb-0" *ngIf="generatedPublicKey">
          <div class="surface-100 p-3 border-round border-1 border-300 flex flex-column gap-2">
            <div class="flex align-items-center justify-content-between">
              <span class="text-xs font-bold text-success"><i class="pi pi-info-circle mr-1"></i>Clé Publique Générée</span>
              <p-button icon="pi pi-copy" [text]="true" size="small" (onClick)="copyToClipboard(generatedPublicKey)" pTooltip="Copier"></p-button>
            </div>
            <code class="text-xs break-all block surface-0 p-2 border-round border-1 border-100" style="max-height: 80px; overflow-y: auto;">{{generatedPublicKey}}</code>
          </div>
        </div>
      </div>
      <ng-template pTemplate="footer">
        <p-button label="Annuler" icon="pi pi-times" [text]="true" severity="secondary" (onClick)="hideDialog()"></p-button>
        <p-button label="Enregistrer" icon="pi pi-check" [disabled]="!newKey.name || !newKey.privateKey" (onClick)="saveKey()" [loading]="isSubmitting"></p-button>
      </ng-template>
    </p-dialog>

    <p-toast position="bottom-right"></p-toast>
```

### frontend/src/app/users/users.ts
```html
<div class="card shadow-1 border-round p-4 surface-card">
      <div class="flex justify-content-between align-items-center mb-4">
        <div>
          <h2 class="text-2xl font-bold m-0">Gestion des utilisateurs</h2>
          <p class="text-secondary mt-1">Administrez les rôles et l'accès des membres de l'équipe</p>
        </div>
        <div class="flex align-items-center gap-3">
          <p-tag severity="info" value="Accès SuperUser" icon="pi pi-shield"></p-tag>
          <span class="p-input-icon-left">
            <i class="pi pi-search"></i>
            <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="p-inputtext-sm" />
          </span>
        </div>
      </div>

      <p-table #dt [value]="users" [rows]="10" [paginator]="true" [rowsPerPageOptions]="[5, 10, 25, 50]"
               [globalFilterFields]="['username', 'displayName', 'email', 'role']"
               responsiveLayout="scroll" styleClass="p-datatable-sm border-round" [rowHover]="true">
        <ng-template pTemplate="header">
          <tr>
            <th pSortableColumn="username">Utilisateur <p-sortIcon field="username"></p-sortIcon></th>
            <th pSortableColumn="email">Email <p-sortIcon field="email"></p-sortIcon></th>
            <th pSortableColumn="role" style="width: 15%">Rôle actuel <p-sortIcon field="role"></p-sortIcon></th>
            <th pSortableColumn="isActive" style="width: 12%">État <p-sortIcon field="isActive"></p-sortIcon></th>
            <th style="width: 25%">Change Role / Action</th>
          </tr>
        </ng-template>
        <ng-template pTemplate="body" let-user>
          <tr>
            <td>
              <div class="flex align-items-center gap-2">
                <img [src]="user.avatarUrl" *ngIf="user.avatarUrl" class="border-circle" style="width: 32px">
                <div class="flex flex-column">
                  <span class="font-bold text-900">{{ user.displayName || user.username }}</span>
                  <span class="text-xs text-secondary" *ngIf="user.displayName">{{ user.username }}</span>
                </div>
              </div>
            </td>
            <td><span class="text-secondary text-sm">{{ user.email }}</span></td>
            <td>
              <span class="text-xs font-bold px-2 py-1 border-round uppercase" 
                    [ngClass]="getRoleClass(user.role)">
                {{ user.role }}
              </span>
            </td>
            <td>
              <p-tag [severity]="user.isActive ? 'success' : 'danger'" 
                     [value]="user.isActive ? 'Actif' : 'Inactif'"
                     [rounded]="true"
                     styleClass="text-xs">
              </p-tag>
            </td>
            <td>
              <div class="flex align-items-center gap-2">
                <p-select [options]="roleOptions" [(ngModel)]="user.pendingRole" 
                         optionLabel="label" optionValue="value" 
                         placeholder="Rôle" [disabled]="user.id === currentUserId"
                         class="w-full" styleClass="p-inputtext-sm">
                </p-select>
                <p-button icon="pi pi-check" size="small" [text]="true"
                         pTooltip="Appliquer le rôle"
                         [disabled]="!user.pendingRole || user.pendingRole === user.role || user.id === currentUserId"
                         (onClick)="updateRole(user)">
                </p-button>
                <p-button [icon]="user.isActive ? 'pi pi-user-minus' : 'pi pi-user-plus'" 
                         size="small" [text]="true"
                         [severity]="user.isActive ? 'danger' : 'success'"
                         [pTooltip]="user.isActive ? 'Suspendre' : 'Activer'"
                         [disabled]="user.id === currentUserId"
                         (onClick)="toggleActive(user)">
                </p-button>
              </div>
            </td>
          </tr>
        </ng-template>
        <ng-template pTemplate="emptymessage">
          <tr>
            <td colspan="5" class="text-center p-5 text-secondary">
              <i class="pi pi-users text-4xl block mb-3"></i>
              Aucun utilisateur trouvé.
            </td>
          </tr>
        </ng-template>
      </p-table>

      <div class="mt-4 p-3 bg-blue-50 border-round border-left-3 border-blue-500">
        <p class="m-0 text-blue-700 text-sm">
          <i class="pi pi-info-circle mr-2"></i>
          En tant que SuperUser, vous pouvez promouvoir d'autres utilisateurs. Vous ne pouvez pas modifier votre propre rôle.
        </p>
      </div>
    </div>
```

### frontend/src/app/vulnerability-table/vulnerability-table.ts
```html
<div class="vulnerability-table p-0">
      <p-table 
        #dt 
        [value]="allMatches" 
        [rows]="10" 
        [paginator]="true" 
        [rowsPerPageOptions]="[5, 10, 25, 50]"
        [responsiveLayout]="'scroll'"
        [globalFilterFields]="['vulnerability.id', 'artifact.name', 'vulnerability.description']"
        selectionMode="single" 
        styleClass="p-datatable-sm border-round"
        [rowHover]="true">
        
        <ng-template pTemplate="caption">
          <div class="flex flex-column md:flex-row md:justify-content-between md:align-items-center gap-3 p-2">
            <div class="flex align-items-center">
              <i class="pi pi-shield text-primary mr-2"></i>
              <span class="font-bold text-lg text-900">Vulnérabilités défectées</span>
            </div>
            <div class="flex flex-column sm:flex-row gap-3 w-full md:w-auto">
              <span class="p-input-icon-left w-full sm:w-auto">
                <i class="pi pi-search"></i>
                <input pInputText type="text" (input)="dt.filterGlobal($any($event.target).value, 'contains')" placeholder="Rechercher..." class="w-full sm:w-auto p-inputtext-sm" />
              </span>
              <div class="flex gap-2 align-items-center">
                 <span class="text-xs font-bold text-secondary mr-1">Filtres :</span>
                 <p-tag value="Critique" severity="danger" class="cursor-pointer" (click)="dt.filter('critical', 'vulnerability.severity', 'equals')" pTooltip="Filtrer Critique"></p-tag>
                 <p-tag value="Haute" severity="warn" class="cursor-pointer" (click)="dt.filter('high', 'vulnerability.severity', 'equals')" pTooltip="Filtrer Haute"></p-tag>
                 <p-button icon="pi pi-filter-slash" [text]="true" size="small" severity="secondary" (click)="dt.reset()" pTooltip="Réinitialiser"></p-button>
              </div>
            </div>
          </div>
        </ng-template>

        <ng-template pTemplate="header">
          <tr>
            <th pSortableColumn="vulnerability.severity" style="width: 130px">Sévérité <p-sortIcon field="vulnerability.severity"></p-sortIcon></th>
            <th pSortableColumn="vulnerability.id" style="width: 160px">ID CVE <p-sortIcon field="vulnerability.id"></p-sortIcon></th>
            <th pSortableColumn="artifact.name">Composant <p-sortIcon field="artifact.name"></p-sortIcon></th>
            <th style="width: 35%">Description</th>
            <th style="width: 120px">État Fix</th>
            <th style="width: 140px">Triage</th>
          </tr>
        </ng-template>

        <ng-template pTemplate="body" let-match>
          <tr class="hover:surface-50 transition-colors">
            <td>
              <span class="vuln-chip" [ngClass]="match.vulnerability.severity.toLowerCase()">
                {{ match.vulnerability.severity | uppercase }}
              </span>
            </td>
            <td>
              <ng-container *ngIf="match.vulnerability.links && match.vulnerability.links.length > 0; else noLink">
                <a [href]="match.vulnerability.links[0]" target="_blank" class="text-primary font-bold no-underline hover:underline flex align-items-center gap-1">
                  {{ match.vulnerability.id }}
                  <i class="pi pi-external-link text-xs"></i>
                </a>
              </ng-container>
              <ng-template #noLink>
                <span class="text-primary font-bold">{{ match.vulnerability.id }}</span>
              </ng-template>
            </td>
            <td>
              <div class="flex flex-column">
                <span class="font-bold text-900 text-sm">{{ match.artifact.name }}</span>
                <span class="text-secondary text-xs mt-1">{{ match.artifact.version }}</span>
              </div>
            </td>
            <td>
              <div class="text-xs text-secondary text-overflow-ellipsis overflow-hidden" [pTooltip]="match.vulnerability.description" tooltipPosition="top">
                {{ match.vulnerability.description | slice:0:100 }}{{ match.vulnerability.description.length > 100 ? '...' : '' }}
              </div>
            </td>
            <td>
              <p-tag [value]="match.vulnerability.fix?.state || 'inconnu'" 
                     [severity]="match.vulnerability.fix?.state === 'fixed' ? 'success' : 'secondary'"
                     styleClass="text-xs">
              </p-tag>
            </td>
            <td class="text-center">
              <div class="flex flex-column align-items-center gap-1 cursor-pointer triage-cell" (click)="openTriage(match)">
                <ng-container *ngIf="getDecision(match) as d; else noDecision">
                  <p-tag [value]="formatStatus(d.status)" [severity]="getVexSeverity(d.status)" styleClass="text-xs"></p-tag>
                  <span class="text-xs text-secondary font-medium" *ngIf="d.response">{{ formatStatus(d.response) }}</span>
                </ng-container>
                <ng-template #noDecision>
                  <p-button label="Évaluer" size="small" [text]="true" severity="secondary" icon="pi pi-shield"></p-button>
                </ng-template>
              </div>
            </td>
          </tr>
        </ng-template>

        <ng-template pTemplate="emptymessage">
          <tr>
            <td colspan="6" class="text-center p-5 text-secondary">
              <i class="pi pi-check-circle text-4xl block mb-3 text-green-500"></i>
              Aucune vulnérabilité trouvée.
            </td>
          </tr>
        </ng-template>
      </p-table>
    </div>

    <!-- Triage Modal -->
    <p-dialog 
      [(visible)]="showModal" 
      [modal]="true" 
      [header]="'Triage: ' + currentMatch?.vulnerability?.id"
      [style]="{ width: '500px' }" 
      [draggable]="false" 
      [resizable]="false">
      
      <div class="flex flex-column gap-4 mt-2">
        <div class="surface-100 p-3 border-round mb-2">
          <p class="m-0 font-bold text-sm">{{ currentMatch?.artifact?.name }} ({{ currentMatch?.artifact?.version }})</p>
          <p class="m-0 text-xs text-secondary mt-1">{{ currentMatch?.vulnerability?.description | slice:0:150 }}...</p>
        </div>

        <div class="p-fluid">
          <label class="block font-bold mb-2 text-sm text-primary">VEX Status</label>
          <p-select [options]="statusOptions" [(ngModel)]="currentDecision.status" optionLabel="label" optionValue="value" placeholder="Select a status"></p-select>
        </div>

        <div class="p-fluid" *ngIf="currentDecision.status === 'not_affected'">
          <label class="block font-bold mb-2 text-sm text-primary">Justification</label>
          <p-select [options]="justificationOptions" [(ngModel)]="currentDecision.justification" optionLabel="label" optionValue="value" placeholder="Select justification"></p-select>
        </div>

        <div class="p-fluid" *ngIf="currentDecision.status !== 'under_investigation'">
          <label class="block font-bold mb-2 text-sm text-primary">Response Action</label>
          <p-select [options]="responseOptions" [(ngModel)]="currentDecision.response" optionLabel="label" optionValue="value" placeholder="Select response action"></p-select>
        </div>

        <div class="p-fluid">
          <label class="block font-bold mb-2 text-sm text-primary">Comments / Analysis</label>
          <textarea pTextarea [(ngModel)]="currentDecision.comment" rows="4" placeholder="Document your analysis and decision reason..."></textarea>
        </div>
      </div>

      <ng-template pTemplate="footer">
        <p-button label="Cancel" icon="pi pi-times" [text]="true" severity="secondary" (onClick)="closeModal()"></p-button>
        <p-button label="Save Decision" icon="pi pi-check" (onClick)="saveDecision()"></p-button>
      </ng-template>
    </p-dialog>
```

