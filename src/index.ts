import JSEncrypt from 'jsencrypt';

// Helper function to fix cookie domain
function fixCookieDomain(cookie: string): string {
  if (cookie.includes('Domain=')) {
    return cookie.replace(/;\s*Domain=[^;]+/gi, '');
  }
  return cookie;
}

export default {
  async fetch(request, env, ctx) {
    const baseUrl = env.BASE_URL;
    const port = env.PORT;
    const username = env.USERNAME;
    const rawPassword = env.PASSWORD;
    const cookieCacheKey = 'proxy_cookie';
    const originCacheKey = 'proxy_origin';

    // Check cache - only store ugreen-proxy-token
    let proxyCookie = await env.UGLINK_CACHE.get(cookieCacheKey);
    let proxyOrigin = await env.UGLINK_CACHE.get(originCacheKey);

    if (!proxyCookie) {
      // First get the encryption public key
      const checkUrl = `${baseUrl}/ugreen/v1/verify/check?token=`;
      const checkResponse = await fetch(checkUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
      });

      if (!checkResponse.ok) {
        console.error('UGLINK Worker: Failed to get encryption key');
        return new Response('Failed to get encryption key', { status: 500 });
      }

      const rsaToken = checkResponse.headers.get('x-rsa-token');
      if (!rsaToken) {
        console.error('UGLINK Worker: No x-rsa-token in check response');
        return new Response('No x-rsa-token in check response', { status: 500 });
      }

      const encryptionPublicKey = atob(rsaToken);
      // Encrypt password with the fetched public key
      const encryptPassword = new JSEncrypt();
      encryptPassword.setPublicKey(encryptionPublicKey);
      const encryptedPassword = encryptPassword.encrypt(rawPassword);

      if (!encryptedPassword) {
        console.error('UGLINK Worker: Failed to encrypt password');
        return new Response('Failed to encrypt password', { status: 500 });
      }

      // Login to get session
      const loginUrl = `${baseUrl}/ugreen/v1/verify/login`;
      const loginResponse = await fetch(loginUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username,
          password: encryptedPassword,
          keepalive: true,
          otp: true,
          is_simple: true
        })
      });

      if (!loginResponse.ok) {
        console.error('UGLINK Worker: Login failed', { status: loginResponse.status });
        return new Response('Failed to login', { status: 500 });
      }

      const loginJson = await loginResponse.json();
      if (loginJson.code !== 200) {
        console.error('UGLINK Worker: Login API error', { msg: loginJson.msg });
        return new Response('Login API error: ' + loginJson.msg, { status: 500 });
      }

      // Decode public key and encrypt token with RSA
      const encodedPublicKey = loginJson.data.public_key;
      const decodedPublicKey = atob(encodedPublicKey);

      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(decodedPublicKey);
      const encryptedToken = encrypt.encrypt(loginJson.data.token);

      if (!encryptedToken) {
        console.error('UGLINK Worker: Failed to encrypt token');
        return new Response('Failed to encrypt token', { status: 500 });
      }

      const loginData = {
        ugreenToken: encryptedToken,
        securityKey: loginJson.data.token_id
      };

      // Fetch docker token with headers
      const apiUrl = `${baseUrl}/ugreen/v1/gateway/proxy/dockerToken?port=${port}`;
      const response = await fetch(apiUrl, {
        headers: {
          'X-Ugreen-Token': loginData.ugreenToken,
          'X-Ugreen-Security-Key': loginData.securityKey
        }
      });

      if (!response.ok) {
        console.error('UGLINK Worker: Failed to fetch docker token', { status: response.status });
        return new Response('Failed to fetch docker token', { status: 500 });
      }

      const data = await response.json();

      if (data.code === 200) {
        const redirectUrl = data.data.redirect_url;
        const redirectResponse = await fetch(redirectUrl, { redirect: 'manual' });
        const redirectHtml = await redirectResponse.text();

        // Extract all cookies from document.cookie assignment
        const cookieMatch = redirectHtml.match(/document\.cookie\s*=\s*'([^']+)'/);
        const setCookie = cookieMatch ? cookieMatch[1] : null;

        if (setCookie) {
          proxyCookie = fixCookieDomain(setCookie);
          proxyOrigin = new URL(redirectUrl).origin;
          // Cache proxy cookie and origin for 1 hour
          await env.UGLINK_CACHE.put(cookieCacheKey, proxyCookie, { expirationTtl: 3600 });
          await env.UGLINK_CACHE.put(originCacheKey, proxyOrigin, { expirationTtl: 3600 });
        } else {
          console.error('UGLINK Worker: No set-cookie in redirect response body');
          return new Response('No set-cookie in redirect response body', { status: 500 });
        }
      } else {
        console.error('UGLINK Worker: API returned error', { msg: data.msg });
        return new Response('API returned error: ' + data.msg, { status: 500 });
      }
    }

    // Reverse proxy to the cached origin with the cookie
    const url = new URL(request.url);
    const proxyUrl = proxyOrigin + url.pathname + url.search;

    // Filter and set headers for proxy
    const proxyHeaders = new Headers();
    for (const [key, value] of request.headers) {
      if (key.toLowerCase() === 'host') continue;
      if (key.toLowerCase() === 'cookie') continue;
      if (key.toLowerCase().startsWith('cf-')) continue;
      proxyHeaders.set(key, value);
    }
    proxyHeaders.set('Host', new URL(proxyOrigin).host);

    // Add X-Forwarded headers for NextCloud to recognize the proxy
    const forwardedProto = request.headers.get('X-Forwarded-Proto') || 'https';
    proxyHeaders.set('X-Forwarded-Proto', forwardedProto);
    proxyHeaders.set('X-Forwarded-Host', new URL(request.url).host);
    proxyHeaders.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');

    // Rewrite Origin and Referer headers for NextCloud CSRF validation
    const originUrl = new URL(request.url);
    proxyHeaders.set('Origin', originUrl.origin);
    proxyHeaders.set('Referer', originUrl.href);

    // Merge client cookies with cached ugreen-proxy-token
    const clientCookies = request.headers.get('Cookie') || '';
    let mergedCookie = clientCookies;

    // Ensure ugreen-proxy-token is always present for Ugreen authentication
    if (!proxyCookie) {
      console.error('UGLINK Worker: ERROR - No cached ugreen-proxy-token in KV!');
      mergedCookie = clientCookies;
    } else if (!clientCookies.includes('ugreen-proxy-token')) {
      // Add cached token to client cookies
      mergedCookie = clientCookies ? `${clientCookies}; ${proxyCookie}` : proxyCookie;
    }

    proxyHeaders.set('Cookie', mergedCookie);

    const proxyResponse = await fetch(proxyUrl, {
      method: request.method,
      headers: proxyHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      redirect: 'manual'  // Intercept redirects to rewrite Location header
    });

    // Handle redirect responses (301, 302, 303, 307, 308)
    if ([301, 302, 303, 307, 308].includes(proxyResponse.status)) {
      const location = proxyResponse.headers.get('Location');

      if (location) {
        // Rewrite Location header to use Workers domain
        const originUrlObj = new URL(proxyOrigin);
        const workersUrl = new URL(request.url);

        let newLocation = location;
        // If location is absolute URL pointing to origin, rewrite to workers domain
        if (location.startsWith(originUrlObj.origin)) {
          newLocation = location.replace(originUrlObj.origin, `${workersUrl.protocol}//${workersUrl.host}`);
        }

        // Create redirect response with rewritten Location
        const redirectHeaders = new Headers(proxyResponse.headers);
        redirectHeaders.set('Location', newLocation);

        return new Response(null, {
          status: proxyResponse.status,
          statusText: proxyResponse.statusText,
          headers: redirectHeaders
        });
      }
    }

    // Forward all Set-Cookie headers from origin server to browser
    const responseHeaders = new Headers(proxyResponse.headers);
    const originSetCookies = proxyResponse.headers.getSetCookie();

    // Check if client request has ugreen-proxy-token
    const hasToken = clientCookies.includes('ugreen-proxy-token');

    // Build final Set-Cookie map with deduplication (keep last value for each cookie name)
    const cookieMap = new Map<string, string>();
    let hasOriginToken = false;

    // Add all origin Set-Cookie headers (passthrough)
    // If origin sends new ugreen-proxy-token, use it and update cache
    for (const cookie of originSetCookies) {
      const cookieName = cookie.split('=')[0].trim();

      if (cookieName === 'ugreen-proxy-token') {
        // Origin sent new token, use it instead of cached one
        hasOriginToken = true;
        cookieMap.set(cookieName, fixCookieDomain(cookie));
        // Update cache with new token (async, don't wait)
        ctx.waitUntil(env.UGLINK_CACHE.put(cookieCacheKey, fixCookieDomain(cookie), { expirationTtl: 3600 }));
      } else {
        // Add other cookies directly (later duplicates will overwrite earlier ones)
        cookieMap.set(cookieName, fixCookieDomain(cookie));
      }
    }

    // Convert map to array
    const finalSetCookies = Array.from(cookieMap.values());

    // Add cached token if client doesn't have it and origin didn't send new one
    if (!hasToken && !hasOriginToken) {
      finalSetCookies.push(fixCookieDomain(proxyCookie));
    }

    // Set all cookies in response
    if (finalSetCookies.length > 0) {
      responseHeaders.delete('Set-Cookie');
      for (const cookie of finalSetCookies) {
        responseHeaders.append('Set-Cookie', cookie);
      }
    }

    return new Response(proxyResponse.body, {
      status: proxyResponse.status,
      statusText: proxyResponse.statusText,
      headers: responseHeaders
    });
  }
};