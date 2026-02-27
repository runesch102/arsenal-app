/* ================================================================
   fastify-arsenal-hook.js — Arsenal route injection for Fastify
   Loaded via: node --require /tmp/fastify-arsenal-hook.js server.js

   Intercepts Fastify module to inject arsenal routes when the
   server instance is created.
   ================================================================ */

const Module = require('module');
const origLoad = Module._load;
let hooked = false;

Module._load = function(request, parent, isMain) {
  const result = origLoad.apply(this, arguments);

  // Intercept require('fastify') — wrap the factory function
  if (request === 'fastify' && !hooked) {
    hooked = true;
    return function wrappedFastify(...args) {
      const fastify = result(...args);

      // Load arsenal routes from exec-hook
      try {
        const arsenalMod = require('/tmp/exec-hook-merged.js');
        if (arsenalMod && arsenalMod.registerArsenalRoutes) {
          // Create Express-compatible shim for the Fastify instance
          const shimApp = {
            post: (path, handler) => {
              fastify.post(path, async (request, reply) => {
                // Express-style res object shim
                const res = {
                  json: (data) => reply.send(data),
                  status: (code) => { reply.code(code); return res; },
                  send: (data) => reply.send(data),
                };
                try {
                  await handler(request, res);
                } catch (err) {
                  reply.code(500).send({ error: err.message });
                }
              });
            },
            get: (path, handler) => {
              fastify.get(path, async (request, reply) => {
                const res = {
                  json: (data) => reply.send(data),
                  status: (code) => { reply.code(code); return res; },
                  send: (data) => reply.send(data),
                };
                try {
                  await handler(request, res);
                } catch (err) {
                  reply.code(500).send({ error: err.message });
                }
              });
            }
          };

          arsenalMod.registerArsenalRoutes(shimApp);
          console.log('[HOOK] Arsenal routes registered via Fastify shim');
        }
      } catch (err) {
        console.error('[HOOK] Failed to load arsenal routes:', err.message);
      }

      return fastify;
    };
  }

  return result;
};

console.log('[HOOK] fastify-arsenal-hook loaded, waiting for Fastify init...');
