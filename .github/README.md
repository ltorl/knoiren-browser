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
<br>

## Running statically through wisp

### Structure

```
knoiren-browser/
├── sw.js           Main proxying logic
└── index.html      Whole UI
```

<br>

### Unblocked links

#### Main link: https://ltorl.github.io/knoiren-browser

Other main links:
1. https://cdn.jsdelivr.net/gh/ltorl/knoiren-svg/open.svg
2. https://cdn.jsdelivr.net/npm/knoiren-browser/open.svg

These wont be blocked because it would break real school sites.

<br>
<br>

Other links:
```
https://jsd.yizex.cn/gh/ltorl/knoiren-svg/open.svg
https://jsd.nmmsl.top/gh/ltorl/knoiren-svg/open.svg
https://jsd.cdn.zzko.cn/gh/ltorl/knoiren-svg/open.svg
https://code.webcache.cn/gh/ltorl/knoiren-svg/open.svg
https://jsd.proxy.aks.moe/gh/ltorl/knoiren-svg/open.svg
https://cdn.jsdmirror.com/gh/ltorl/knoiren-svg/open.svg
https://jsdelivr.b-cdn.net/gh/ltorl/knoiren-svg/open.svg
https://jsd.onmicrosoft.cn/gh/ltorl/knoiren-svg/open.svg
https://cdn.jsdelivr.net.cn/gh/ltorl/knoiren-svg/open.svg
https://cdn.statically.io/gh/ltorl/knoiren-svg@main/open.svg
```

<br>

These all use a public wisp which may have some site limitations. <br>

You can run a wisp server locally with:

```bash
npx @mercuryworkshop/wisp-js
```

Then enter `ws://localhost:5001` in the settings page.

<br>
<br>
<br>
<br>

## Running through node backend

### Structure

```
knoiren-browser/
└── index.js         Whole UI + Proxying logic
```

### Quick start

One line, no cloning:

```bash
curl -sL https://cdn.jsdelivr.net/gh/ltorl/knoiren-browser/index.js | node
```

Then open **http://localhost:8080**.

<br>

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

<br>
<br>
<br>
<br>

## Features

<table>
<tr>
<td width="50%" valign="top">

### The browser

- **Real tabs**: drag to reorder, pin, duplicate, close others / left / right
- **Mute tabs**: a speaker shows on tabs playing sound; click it to silence the tab
- **Bookmarks bar**: star any page, and **bookmarklets** run inside the page
- **Pop-up control**: links open as new tabs, and scripted pop-ups ask first
- **Close warning**: will stop teacher from closing it through an extension
<br>
</td>
<td width="50%" valign="top">

### The Peekaboom proxy

- Rewrites **HTML, CSS and JavaScript** as you are actively browsing
- Handles **WebSockets**, **EventSource**, **sendBeacon** and **workers**
- A **service worker** gets requests past the rewriter
- Keeps each site's **cookies** apart
- Patches `location`, `document.domain`, `top` / `parent` so sites think they're at home
- Mutes **audio, video, Web Audio and speech**, even inside shadow DOM and nested frames

</td>
</tr>
</table>

<br>
<br>
<br>

<details>
<summary>
<h2>How it works - wisp proxy</h2>
</summary>

```
                 ┌────────────────────────────┐
  you  ───────▶  │ Knoiren UI      index.html │   tabs, bookmarks, settings
                 └─────────────┬──────────────┘
                               │ 
                 ┌─────────────▼──────────────┐
                 │ Peekaboom proxy      sw.js │   fetches + rewrites every page
                 └─────────────┬──────────────┘
                               ▼
                 ┌─────────────▼──────────────┐
                 │ Wisp server          [set] │   forwards fetch request
                 └─────────────┬──────────────┘
                               ▼
                         the real web
                          
```

<br>

### Configuration 

Everything is optional. Set these in settings:

| Setting        | Default           | What it does                                                                 |
| -------------- | ----------------- | ---------------------------------------------------------------------------- |
| `WISP RELAY`   | `wss://anura.pro` | forwards fetch request                                                       |


</details>



<details>
<summary>
<h2>How it works - node server</h2>
</summary>

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

### Configuration 

Everything is optional. Set these as environment variables:

| Variable       | Default   | What it does                                                                 |
| -------------- | --------- | ---------------------------------------------------------------------------- |
| `UI_PORT`      | `8080`    | Port for the browser UI                                                      |
| `PORT`         | `8787`    | Port for the proxy                                                           |
| `HOST`         | `0.0.0.0` | Interface both servers listen on                                             |

</details>

<details>
<summary> 
<h2>Embedding the proxy in your own site</h2>
</summary>

<br>

Peekaboom works without the UI too. Any page can frame a proxied site:

```html
<iframe src="https://peekaboom-proxy.github.io/__px/https://example.com/"></iframe>
```

This will use `wss://anura.pro`. This is the same proxying logic used in this site.

</details>


<br>
<br>
<br>
<br>
<br>
<br>

