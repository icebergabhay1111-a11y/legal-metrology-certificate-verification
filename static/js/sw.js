/* Service worker: keeps the offline checker available with no network.
   Only the checker and its files are cached. Status pages are never cached,
   because a status must be worked out on the day it is checked. */
var CACHE = "sd-offline-v1";
var FILES = ["/offline", "/keys.json", "/static/css/app.css", "/static/js/a11y.js",
             "/static/js/offline.js", "/manifest.webmanifest", "/static/icon-192.png"];

self.addEventListener("install", function (event) {
  event.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(FILES); }));
  self.skipWaiting();
});

self.addEventListener("activate", function (event) {
  event.waitUntil(caches.keys().then(function (names) {
    return Promise.all(names.filter(function (n) { return n !== CACHE; })
                            .map(function (n) { return caches.delete(n); }));
  }));
  self.clients.claim();
});

// Network first for the files above (so they stay current), cache when offline.
self.addEventListener("fetch", function (event) {
  var url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin || FILES.indexOf(url.pathname) < 0) {
    return;
  }
  event.respondWith(
    fetch(event.request).then(function (response) {
      var copy = response.clone();
      if (response.ok) { caches.open(CACHE).then(function (c) { c.put(event.request, copy); }); }
      return response;
    }).catch(function () { return caches.match(event.request); })
  );
});
