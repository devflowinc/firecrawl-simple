/**
 * Check if an IPv4 address is in a private range (RFC 1918 + localhost + link-local)
 * This prevents SSRF attacks by blocking requests to internal network addresses
 */
function isIPv4Private(ip: string): boolean {
  const octets = ip.split('.').map(Number);

  if (octets.length !== 4 || octets.some(octet => isNaN(octet) || octet < 0 || octet > 255)) {
    return false;
  }

  // 10.0.0.0/8 - Private network
  if (octets[0] === 10) {
    return true;
  }

  // 172.16.0.0/12 - Private network (CRITICAL FIX: was previously not checked correctly)
  // This range is 172.16.0.0 - 172.31.255.255
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) {
    return true;
  }

  // 192.168.0.0/16 - Private network
  if (octets[0] === 192 && octets[1] === 168) {
    return true;
  }

  // 127.0.0.0/8 - Loopback
  if (octets[0] === 127) {
    return true;
  }

  // 169.254.0.0/16 - Link-local
  if (octets[0] === 169 && octets[1] === 254) {
    return true;
  }

  // 0.0.0.0/8 - Current network
  if (octets[0] === 0) {
    return true;
  }

  return false;
}

/**
 * Check if a hostname resolves to a private IP or is a private hostname
 */
function isPrivateHostname(hostname: string): boolean {
  // Check for localhost variants
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) {
    return true;
  }

  // Check for .local domains (mDNS)
  if (hostname.endsWith('.local')) {
    return true;
  }

  // Check for internal domains
  if (hostname.endsWith('.internal')) {
    return true;
  }

  // Check if hostname is an IP address
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    return isIPv4Private(hostname);
  }

  return false;
}

/**
 * Blocked non-web protocols that should not be crawled
 */
const BLOCKED_PROTOCOLS = ['mailto:', 'tel:', 'telnet:', 'ftp:', 'ftps:', 'ssh:', 'file:', 'data:', 'javascript:'];

export const protocolIncluded = (url: string) => {
  // if :// not in the start of the url assume http (maybe https?)
  // regex checks if :// appears before any .
  return /^([^.:]+:\/\/)/.test(url);
};

const getURLobj = (s: string) => {
  // URL fails if we dont include the protocol ie google.com
  let error = false;
  let urlObj = {};
  try {
    urlObj = new URL(s);
  } catch (err) {
    error = true;
  }
  return { error, urlObj };
};

export const checkAndUpdateURL = (url: string) => {
  if (!protocolIncluded(url)) {
    url = `http://${url}`;
  }

  const { error, urlObj } = getURLobj(url);
  if (error) {
    throw new Error("Invalid URL");
  }

  const typedUrlObj = urlObj as URL;

  // Check for blocked non-web protocols (PR #2357)
  if (BLOCKED_PROTOCOLS.includes(typedUrlObj.protocol)) {
    throw new Error(`URL uses a non-web protocol: ${typedUrlObj.protocol}`);
  }

  if (typedUrlObj.protocol !== "http:" && typedUrlObj.protocol !== "https:") {
    throw new Error("Invalid URL");
  }

  // SSRF Protection (Issue #2070) - Block private IP addresses and hostnames
  if (isPrivateHostname(typedUrlObj.hostname)) {
    throw new Error("Access to private/internal hosts is not allowed");
  }

  return { urlObj: typedUrlObj, url: url };
};

export const checkUrl = (url: string) => {
  const { error, urlObj } = getURLobj(url);
  if (error) {
    throw new Error("Invalid URL");
  }

  const typedUrlObj = urlObj as URL;

  // Check for blocked non-web protocols (PR #2357)
  if (BLOCKED_PROTOCOLS.includes(typedUrlObj.protocol)) {
    throw new Error(`URL uses a non-web protocol: ${typedUrlObj.protocol}`);
  }

  if (typedUrlObj.protocol !== "http:" && typedUrlObj.protocol !== "https:") {
    throw new Error("Invalid URL");
  }

  if ((url.split(".")[0].match(/:/g) || []).length !== 1) {
    throw new Error("Invalid URL. Invalid protocol."); // for this one: http://http://example.com
  }

  // SSRF Protection (Issue #2070) - Block private IP addresses and hostnames
  if (isPrivateHostname(typedUrlObj.hostname)) {
    throw new Error("Access to private/internal hosts is not allowed");
  }

  return url;
};

/**
 * Same domain check
 * It checks if the domain of the url is the same as the base url
 * It accounts true for subdomains and www.subdomains
 * @param url 
 * @param baseUrl 
 * @returns 
 */
export function isSameDomain(url: string, baseUrl: string) {
  const { urlObj: urlObj1, error: error1 } = getURLobj(url);
  const { urlObj: urlObj2, error: error2 } = getURLobj(baseUrl);

  if (error1 || error2) {
    return false;
  }

  const typedUrlObj1 = urlObj1 as URL;
  const typedUrlObj2 = urlObj2 as URL;

  const cleanHostname = (hostname: string) => {
    return hostname.startsWith('www.') ? hostname.slice(4) : hostname;
  };

  const domain1 = cleanHostname(typedUrlObj1.hostname).split('.').slice(-2).join('.');
  const domain2 = cleanHostname(typedUrlObj2.hostname).split('.').slice(-2).join('.');

  return domain1 === domain2;
}


export function isSameSubdomain(url: string, baseUrl: string) {
  const { urlObj: urlObj1, error: error1 } = getURLobj(url);
  const { urlObj: urlObj2, error: error2 } = getURLobj(baseUrl);

  if (error1 || error2) {
    return false;
  }

  const typedUrlObj1 = urlObj1 as URL;
  const typedUrlObj2 = urlObj2 as URL;

  const cleanHostname = (hostname: string) => {
    return hostname.startsWith('www.') ? hostname.slice(4) : hostname;
  };

  const domain1 = cleanHostname(typedUrlObj1.hostname).split('.').slice(-2).join('.');
  const domain2 = cleanHostname(typedUrlObj2.hostname).split('.').slice(-2).join('.');

  const subdomain1 = cleanHostname(typedUrlObj1.hostname).split('.').slice(0, -2).join('.');
  const subdomain2 = cleanHostname(typedUrlObj2.hostname).split('.').slice(0, -2).join('.');

  // Check if the domains are the same and the subdomains are the same
  return domain1 === domain2 && subdomain1 === subdomain2;
}


export const checkAndUpdateURLForMap = (url: string) => {
  if (!protocolIncluded(url)) {
    url = `http://${url}`;
  }
  // remove last slash if present
  if (url.endsWith("/")) {
    url = url.slice(0, -1);
  }


  const { error, urlObj } = getURLobj(url);
  if (error) {
    throw new Error("Invalid URL");
  }

  const typedUrlObj = urlObj as URL;

  if (typedUrlObj.protocol !== "http:" && typedUrlObj.protocol !== "https:") {
    throw new Error("Invalid URL");
  }

  // remove any query params
  url = url.split("?")[0].trim();

  return { urlObj: typedUrlObj, url: url };
};





export function removeDuplicateUrls(urls: string[]): string[] {
  const urlMap = new Map<string, string>();

  for (const url of urls) {
    const parsedUrl = new URL(url);
    const protocol = parsedUrl.protocol;
    const hostname = parsedUrl.hostname.replace(/^www\./, '');
    const path = parsedUrl.pathname + parsedUrl.search + parsedUrl.hash;
    
    const key = `${hostname}${path}`;
    
    if (!urlMap.has(key)) {
      urlMap.set(key, url);
    } else {
      const existingUrl = new URL(urlMap.get(key)!);
      const existingProtocol = existingUrl.protocol;
      
      if (protocol === 'https:' && existingProtocol === 'http:') {
        urlMap.set(key, url);
      } else if (protocol === existingProtocol && !parsedUrl.hostname.startsWith('www.') && existingUrl.hostname.startsWith('www.')) {
        urlMap.set(key, url);
      }
    }
  }

  return [...new Set(Array.from(urlMap.values()))];
}