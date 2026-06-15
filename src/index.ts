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

    // Ugreen authentication flow - only runs when cache is empty
    if (!proxyCookie) {
      // First get the encryption public key
      const checkResponse = await fetch(`${baseUrl}/ugreen/v1/verify/check?token=`, {
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

      // Encrypt password with RSA public key
      const encryptPassword = new JSEncrypt();
      encryptPassword.setPublicKey(atob(rsaToken));
      const encryptedPassword = encryptPassword.encrypt(rawPassword);

      if (!encryptedPassword) {
        console.error('UGLINK Worker: Failed to encrypt password');
        return new Response('Failed to encrypt password', { status: 500 });
      }

      // Login to Ugreen with encrypted password
      const loginResponse = await fetch(`${baseUrl}/ugreen/v1/verify/login`, {
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

      // Encrypt token with second RSA key from login response
      const encrypt = new JSEncrypt();
      encrypt.setPublicKey(atob(loginJson.data.public_key));
      const encryptedToken = encrypt.encrypt(loginJson.data.token);

      if (!encryptedToken) {
        console.error('UGLINK Worker: Failed to encrypt token');
        return new Response('Failed to encrypt token', { status: 500 });
      }

      // Fetch docker token using encrypted credentials
      const tokenResponse = await fetch(`${baseUrl}/ugreen/v1/gateway/proxy/dockerToken?port=${port}`, {
        headers: {
          'X-Ugreen-Token': encryptedToken,
          'X-Ugreen-Security-Key': loginJson.data.token_id
        }
      });

      if (!tokenResponse.ok) {
        console.error('UGLINK Worker: Failed to fetch docker token', { status: tokenResponse.status });
        return new Response('Failed to fetch docker token', { status: 500 });
      }

      const data = await tokenResponse.json();

      if (data.code === 200) {
        // Fetch redirect URL to extract proxy token cookie
        const redirectResponse = await fetch(data.data.redirect_url, { redirect: 'manual' });
        const redirectHtml = await redirectResponse.text();

        // Extract cookie from JavaScript document.cookie assignment
        const cookieMatch = redirectHtml.match(/document\.cookie\s*=\s*'([^']+)'/);
        const setCookie = cookieMatch ? cookieMatch[1] : null;

        if (setCookie) {
          proxyCookie = fixCookieDomain(setCookie);
          proxyOrigin = new URL(data.data.redirect_url).origin;
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

    // Build proxy URL from cached origin
    const url = new URL(request.url);
    const proxyUrl = proxyOrigin + url.pathname + url.search;

    // Filter and set headers for proxy request
    const proxyHeaders = new Headers();
    for (const [key, value] of request.headers) {
      if (['host', 'cookie'].includes(key.toLowerCase())) continue;
      if (key.toLowerCase().startsWith('cf-')) continue;
      proxyHeaders.set(key, value);
    }
    proxyHeaders.set('Host', new URL(proxyOrigin).host);

    // Add X-Forwarded headers for NextCloud to recognize the proxy
    proxyHeaders.set('X-Forwarded-Proto', request.headers.get('X-Forwarded-Proto') || 'https');
    proxyHeaders.set('X-Forwarded-Host', url.host);
    proxyHeaders.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');

    // Rewrite Origin and Referer headers for NextCloud CSRF validation
    proxyHeaders.set('Origin', url.origin);
    proxyHeaders.set('Referer', url.href);

    // Ensure ugreen-proxy-token is always present for Ugreen authentication
    const clientCookies = request.headers.get('Cookie') || '';
    let mergedCookie = clientCookies;
    if (proxyCookie && !clientCookies.includes('ugreen-proxy-token')) {
      mergedCookie = clientCookies ? `${clientCookies}; ${proxyCookie}` : proxyCookie;
    }
    proxyHeaders.set('Cookie', mergedCookie);

    // Forward request to origin server
    const proxyResponse = await fetch(proxyUrl, {
      method: request.method,
      headers: proxyHeaders,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      redirect: 'manual'  // Intercept redirects to rewrite Location header
    });

    // Handle redirect responses - rewrite Location header to use Workers domain
    const location = proxyResponse.headers.get('Location');
    if ([301, 302, 303, 307, 308].includes(proxyResponse.status) && location) {
      // Rewrite absolute Location URL from origin to Workers domain
      const originUrlObj = new URL(proxyOrigin);
      const newLocation = location.startsWith(originUrlObj.origin)
        ? location.replace(originUrlObj.origin, `${url.protocol}//${url.host}`)
        : location;

      const redirectHeaders = new Headers(proxyResponse.headers);
      redirectHeaders.set('Location', newLocation);
      return new Response(null, {
        status: proxyResponse.status,
        statusText: proxyResponse.statusText,
        headers: redirectHeaders
      });
    }

    // Forward all Set-Cookie headers from origin server to browser
    const responseHeaders = new Headers(proxyResponse.headers);
    const originSetCookies = proxyResponse.headers.getSetCookie();
    const hasToken = clientCookies.includes('ugreen-proxy-token');

    // Build final Set-Cookie array - if origin sends new ugreen-proxy-token, use it and update cache
    const finalSetCookies: string[] = [];
    let hasOriginToken = false;

    for (const cookie of originSetCookies) {
      const fixedCookie = fixCookieDomain(cookie);
      if (cookie.split('=')[0].trim() === 'ugreen-proxy-token') {
        // Origin sent new token - use it and update cache
        hasOriginToken = true;
        ctx.waitUntil(env.UGLINK_CACHE.put(cookieCacheKey, fixedCookie, { expirationTtl: 3600 }));
      }
      finalSetCookies.push(fixedCookie);
    }

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