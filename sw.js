const V='wingman-v17',FILES=['./','index.html','manifest.webmanifest','icons/icon-192.png','icons/icon-512.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(FILES)));self.skipWaiting();});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V).map(x=>caches.delete(x)))));self.clients.claim();});
self.addEventListener('fetch',e=>{if(e.request.method!=='GET'||new URL(e.request.url).origin!==location.origin)return;e.respondWith(fetch(e.request).then(r=>{const c=r.clone();caches.open(V).then(x=>x.put(e.request,c));return r;}).catch(()=>caches.match(e.request)));});
self.addEventListener('push',e=>{let d={};try{d=e.data?e.data.json():{};}catch(x){d={title:'WingMan',body:e.data?e.data.text():''};}
  e.waitUntil(self.registration.showNotification(d.title||'WingMan',{body:d.body||'',tag:d.tag||undefined,icon:'icons/icon-192.png',badge:'icons/icon-192.png',data:{url:d.url||'#alerts'}}));});
self.addEventListener('notificationclick',e=>{e.notification.close();const url=(e.notification.data&&e.notification.data.url)||'#alerts';
  e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(cs=>{for(const c of cs){if('focus' in c){c.focus();if('navigate' in c){c.navigate(new URL(url,self.registration.scope).href).catch(()=>{});}return;}}return self.clients.openWindow(new URL(url,self.registration.scope).href);}));});
