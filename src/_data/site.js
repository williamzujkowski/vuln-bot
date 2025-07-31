/**
 * Site-wide data for the vulnerability intelligence platform
 */

module.exports = {
  title: "Vulnerability Intelligence Dashboard",
  description: "High-risk CVE intelligence platform tracking Critical & High severity vulnerabilities with EPSS ≥ 70% exploitation probability",
  url: process.env.NODE_ENV === 'production' 
    ? 'https://williamzujkowski.github.io/vuln-bot'
    : 'http://localhost:8080',
  pathPrefix: process.env.NODE_ENV === 'production' ? '/vuln-bot' : '',
  author: {
    name: "Vulnerability Intelligence System",
    email: "noreply@example.com"
  },
  buildTime: new Date().toISOString(),
  version: "2.0.0",
  
  // Analytics and monitoring
  analytics: {
    enabled: process.env.NODE_ENV === 'production',
    trackingId: process.env.GA_TRACKING_ID || null
  },
  
  // Security settings
  security: {
    csp: {
      enabled: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "https://unpkg.com", "https://cdn.jsdelivr.net"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'", "https:"],
        'connect-src': ["'self'"]
      }
    }
  },
  
  // Feature flags
  features: {
    staticCvePages: true,
    alpineJsDashboard: true,
    searchIndex: true,
    charts: true,
    exportFeatures: true,
    accessibility: true
  },
  
  // Data sources and refresh rates
  dataSources: {
    cveList: {
      name: "CVEProject/cvelistV5",
      url: "https://github.com/CVEProject/cvelistV5",
      refreshMinutes: 240 // 4 hours
    },
    epss: {
      name: "EPSS API",
      url: "https://api.first.org/data/v1/epss",
      refreshMinutes: 1440 // 24 hours
    },
    githubAdvisory: {
      name: "GitHub Security Advisory Database",
      url: "https://github.com/advisories",
      refreshMinutes: 240 // 4 hours
    }
  },
  
  // Vulnerability filtering criteria
  criteria: {
    severities: ["CRITICAL", "HIGH"],
    minEpssScore: 70,
    minRiskScore: 70,
    yearRange: [2024, 2025]
  }
};