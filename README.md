<div align="center">

<img width="760" height="224" alt="banner" src="https://github.com/user-attachments/assets/160bae9d-e74c-4b9c-9b7f-b510d86442ce" />

### A whole web browser and proxy in one file.

Tabs, bookmarks, games, and a proxy with compatibility close to Scramjet and Ultraviolet.<br>
Zero-dependency!

<br>

![Node](https://img.shields.io/badge/node-20.19%2B-8b5cf6?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-0-7c8cf8?style=for-the-badge)
![Single file](https://img.shields.io/badge/single-file-60a5fa?style=for-the-badge)
![License](https://img.shields.io/badge/license-GPL--3.0-22d3ee?style=for-the-badge)

</div>

<br>

## Quick start

One line, no cloning:

```bash
curl -sL https://cdn.jsdelivr.net/gh/ltorl/knoiren-browser/index.js | node
```

Then open **http://localhost:8080**.

<details>
<summary><b>Other ways to run it</b></summary>

<br>

**From a clone**

```bash
git clone https://github.com/ltorl/knoiren-browser
cd knoiren-browser
node index.js
```

**Older Node** (before 22.7 / 20.19) needs to be told the piped code is a module:

```bash
curl -sL https://cdn.jsdelivr.net/gh/ltorl/knoiren-browser/index.js | node --input-type=module
```

**Custom ports**

```bash
curl -sL https://cdn.jsdelivr.net/gh/ltorl/knoiren-browser/index.js | PORT=9000 UI_PORT=9001 node
```

</details>

<details>
<summary><b>Hosting</b></summary>

<br>

When using a hosting provider, it's best to separate the frontend and the backend because you may not be able to specify which port gets forwarded.

I'd recommend using GitHub Pages or other free static hosting for the frontend (`index.html`) and hosting the backend (`proxy.js`) on a separate service.

#### Backend configs:

Build Command:
```bash
echo "no build"
```

Start Command:
```bash
node proxy.js
```


For your own frontend configuration, use:

```js
UI_ORIGIN = "https://your-site.com"
```

To use this repository's GitHub Pages frontend, use:

```js
UI_ORIGIN = "https://ltorl.github.io"
```

It would be greatly appreciated if you hosted a backend and submitted a pull request to this README so others can use it.

</details>

<br>

## Current proxy backends
For use with the github pages frontend at: https://ltorl.github.io/knoiren-browser <br>
<br>
(Copy and put into settings page):
1. https://knoiren-browser-backend.onrender.com
2. https://forgery-sophisticated-fish.abasthan.app
3. https://knoiren-backend.de.deplexo.com/

<br>

## Features

<table>
<tr>
<td width="50%" valign="top">

### The browser

- **Real tabs**: drag to reorder, pin, duplicate, close others / left / right
- **Mute tabs**: a speaker shows on tabs playing sound; click it to silence the tab
- **Smart address bar**: type a URL or search DuckDuckGo, with live suggestions
- **Bookmarks bar**: star any page, and **bookmarklets** run inside the page
- **Games sidebar**: a built-in list of game sites, one click away
- **Pop-up control**: links open as new tabs, and scripted pop-ups ask first
- **Close warning**: will stop teacher from closing it through an extension

</td>
<td width="50%" valign="top">

### The Peekaboom proxy

- Rewrites **HTML, CSS and JavaScript** on the fly
- Handles **WebSockets**, **EventSource**, **sendBeacon** and **workers**
- A **service worker** catches requests that slip past the rewriter
- Keeps each site's **cookies** apart
- Patches `location`, `document.domain`, `top` / `parent` and frames so sites think they're at home
- Mutes **audio, video, Web Audio and speech**, even inside shadow DOM and nested frames

</td>
</tr>
</table>

<br>

## How it works

```
                 ┌────────────────────────────┐
  you  ───────▶  │  Knoiren UI      :8080     │   tabs, bookmarks, settings
                 └─────────────┬──────────────┘
                               │ <iframe> per tab
                 ┌─────────────▼──────────────┐
                 │  Peekaboom proxy :8787     │   fetches + rewrites every page
                 └─────────────┬──────────────┘
                               ▼
                          the real web
```

The UI and the proxy run on **two separate ports on purpose**. They're different origins, so a proxied site can never read the browser's own storage, bookmarks or tabs. The UI only talks to pages through `postMessage`, and only messages from the UI's own origin can run bookmarklets or mute a tab.

Everything lives in **`index.js`**: both HTTP servers, the proxy, an HTML rewriter, the script injected into every page, and the full browser UI.

<br>

## Configuration

Everything is optional. Set these as environment variables:

| Variable       | Default   | What it does                                                                 |
| -------------- | --------- | ---------------------------------------------------------------------------- |
| `UI_PORT`      | `8080`    | Port for the browser UI                                                      |
| `PORT`         | `8787`    | Port for the proxy                                                           |
| `HOST`         | `0.0.0.0` | Interface both servers listen on                                             |
| `PROXY_ORIGIN` | *(auto)*  | Public address of the proxy, if it's behind a reverse proxy (e.g. `https://proxy.example.com`) |
| `UI_ORIGIN`    | *(auto)*  | Public address of the UI, as the browser sees it                             |
| `NO_COLOR`     | *(unset)* | Turns off the colorful startup banner                                        |

<details>
<summary><b>Deploying behind a reverse proxy</b></summary>

<br>

Give the UI and the proxy their own hostnames, and tell Knoiren where they are:

```bash
PROXY_ORIGIN=https://proxy.example.com \
UI_ORIGIN=https://browse.example.com \
node index.js
```

Point `browse.example.com` at port `8080` and `proxy.example.com` at port `8787`. Keep them on **different hostnames**, because that separation is what keeps sites away from the UI.

</details>

<details>
<summary><b>Embedding the proxy in your own page</b></summary>

<br>

Peekaboom works without the UI too. Any page can frame a proxied site:

```html
<iframe src="http://localhost:8787/__px/https://example.com/"></iframe>
```

</details>

<br>

## License

[GPL-3.0](LICENSE)
